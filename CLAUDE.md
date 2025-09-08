# Project Guidelines

## Development Commands
- Check for lint/typecheck commands in package.json or other config files when making changes
- When adding a new JavaScript controller or creating them with `./bin/rails generate stimulus controllerName`, always run `./bin/rails stimulus:manifest:update` afterwards.

## HTTP Requests
- Always use faraday for http requests as opposed to other libraries
- even tho it seems like the api paths should start with /v1 it's /api/v1 even with the weird mounting thing