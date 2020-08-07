# Pulumi Htpasswd

A pulumi resource for generating Htpasswd files.

## Installation

```bash
npm install --save --save-exact pulumi-htpasswd
```

## Example

```typescript
import { Htpasswd } from 'pulumi-htpasswd';

const credentials = new Htpasswd('credentials', {
    algorithm: HtpasswdAlgorithm.Bcrypt,
    entries: [{
        // example with a specific username + password
        username: 'user1',
        password: 'mypassword',
    }, {
        // example where the password will be generated
        username: 'user2',
    }],
});

// the resulting htpasswd file
export const htpasswdFile = credentials.result;

// the plaintext entries that
export const plaintextEntries = credentials.plaintextEntries
```
