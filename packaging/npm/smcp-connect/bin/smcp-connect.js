#!/usr/bin/env node
'use strict';

require('../lib/index')
  .main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  });
