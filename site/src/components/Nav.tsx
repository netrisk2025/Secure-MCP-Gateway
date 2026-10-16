import Link from "next/link";

const LINKS = [
  { href: "/architecture/", label: "Architecture" },
  { href: "/elements/", label: "Elements" },
  { href: "/interfaces/", label: "Interfaces" },
  { href: "/requirements/", label: "Requirements" },
  { href: "/security/", label: "Security controls" },
  { href: "/clients/", label: "Clients" },
  { href: "/docs/", label: "Documents" },
];

export default function Nav() {
  return (
    <header className="nav">
      <Link href="/" className="wordmark">
        Secure MCP Gateway
      </Link>
      <nav aria-label="Primary">
        {LINKS.map((l) => (
          <Link key={l.href} href={l.href}>
            {l.label}
          </Link>
        ))}
      </nav>
    </header>
  );
}
