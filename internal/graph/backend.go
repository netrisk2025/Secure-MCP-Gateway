package graph

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/config"
)

// Backend is the graph database connection (I-36). Only the Data Access
// Service calls it, and only with statements from the verified catalog.
// *Neo4j implements it; tests use *Fake.
type Backend interface {
	// Write runs the statements in order in one managed write
	// transaction and returns each statement's rows.
	Write(ctx context.Context, stmts []Statement) ([][]Row, error)
	// Read runs one statement in a managed read transaction.
	Read(ctx context.Context, st Statement) ([]Row, error)
	// Close releases the connection.
	Close(ctx context.Context) error
}

// TxTimeout bounds every transaction on the server (bounded query cost).
const TxTimeout = 15 * time.Second

// Neo4j is the Backend for Neo4j Community Edition over Bolt.
type Neo4j struct {
	driver   neo4j.Driver
	database string
}

// NewNeo4j creates a driver for uri. It does not connect; the first
// statement does. Statements other than the catalog's are impossible
// because Op values exist only in the catalog.
func NewNeo4j(uri, user, password, database string) (*Neo4j, error) {
	d, err := neo4j.NewDriver(uri, neo4j.BasicAuth(user, password, ""), func(c *config.Config) {
		c.MaxConnectionPoolSize = 8
		c.ConnectionAcquisitionTimeout = 5 * time.Second
		c.SocketConnectTimeout = 5 * time.Second
		c.MaxTransactionRetryTime = 10 * time.Second
		c.UserAgent = "smcp-gateway-das"
	})
	if err != nil {
		return nil, err
	}
	return &Neo4j{driver: d, database: database}, nil
}

func (n *Neo4j) session(ctx context.Context, mode neo4j.AccessMode) neo4j.Session {
	return n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: mode, DatabaseName: n.database})
}

// driverParams converts typed parameter values into the shapes the Bolt
// encoder accepts.
func driverParams(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		switch t := v.(type) {
		case []map[string]any:
			l := make([]any, len(t))
			for i, r := range t {
				l[i] = driverParams(r)
			}
			out[k] = l
		case map[string]any:
			out[k] = driverParams(t)
		case []string:
			l := make([]any, len(t))
			for i, s := range t {
				l[i] = s
			}
			out[k] = l
		default:
			out[k] = v
		}
	}
	return out
}

// Write implements Backend. The transaction function contains only
// database work (SR-7.1-1): the driver may retry it.
func (n *Neo4j) Write(ctx context.Context, stmts []Statement) ([][]Row, error) {
	s := n.session(ctx, neo4j.AccessModeWrite)
	defer s.Close(ctx)
	res, err := s.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		out := make([][]Row, len(stmts))
		for i, st := range stmts {
			rows, err := runTx(ctx, tx, st)
			if err != nil {
				return nil, err
			}
			out[i] = rows
		}
		return out, nil
	}, neo4j.WithTxTimeout(TxTimeout))
	if err != nil {
		return nil, classify(err)
	}
	return res.([][]Row), nil
}

// Read implements Backend.
func (n *Neo4j) Read(ctx context.Context, st Statement) ([]Row, error) {
	s := n.session(ctx, neo4j.AccessModeRead)
	defer s.Close(ctx)
	res, err := s.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return runTx(ctx, tx, st)
	}, neo4j.WithTxTimeout(TxTimeout))
	if err != nil {
		return nil, classify(err)
	}
	return res.([]Row), nil
}

func runTx(ctx context.Context, tx neo4j.ManagedTransaction, st Statement) ([]Row, error) {
	r, err := tx.Run(ctx, st.Op.text, driverParams(st.Params))
	if err != nil {
		return nil, err
	}
	recs, err := r.Collect(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]Row, len(recs))
	for i, rec := range recs {
		rows[i] = rec.AsMap()
	}
	return rows, nil
}

// Close implements Backend.
func (n *Neo4j) Close(ctx context.Context) error { return n.driver.Close(ctx) }

// classify marks connectivity failures as ErrUnavailable so that callers
// can tell an outage from a rejected statement.
func classify(err error) error {
	var cerr *neo4j.ConnectivityError
	if errors.As(err, &cerr) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var nerr *neo4j.Neo4jError
	if errors.As(err, &nerr) && (nerr.Code == "Neo.ClientError.Security.Unauthorized" || nerr.Code == "Neo.TransientError.General.DatabaseUnavailable") {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return err
}
