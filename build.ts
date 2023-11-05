
import { writeFileSync, copyFileSync } from 'fs';

const packageJson = require('./package.json');

const { scripts, devDependencies, ...rest } = packageJson;

writeFileSync('dist/package.json', JSON.stringify(rest, null, '\t'));

copyFileSync('.npmignore', 'dist/.npmignore');
