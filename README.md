IMQS Authentication System
==========================

Other references
1. [Overview](./docs/Overview.md)
2. [API](./docs/API.md)
3. [Config schema](./docs/config/imqsauth.json)


## Building

To build imqsauth:

	go build imqsauth.go

## Testing

Note that github.com/IMQS/authaus has it's own set of tests, which we run
in it's own CI job.

`imqsauth` has two set of tests: Go and ruby. The ruby tests hit the REST API.

The following block demonstrates running all of the tests:

	go test github.com/IMQS/imqsauth/auth
	go build imqsauth.go
	gem install rest-client
	ruby resttest.rb

## Running

To run imqsauth and create a local postgres database, do

	./imqsauth -c=example-local.conf createdb

You will need to have the appropriate postgres login setup on your database. See the 
`example-local.conf` file for those details.

Next, reset the authorization groups 'admin' and 'enabled'

	./imqsauth -c=example-local.conf resetauthgroups

Create a user called 'root'

	./imqsauth -c=example-local.conf createuser root PASSWORD

Grant the 'root' user 'admin' and 'enabled' rights

	./imqsauth -c=example-local.conf permgroupadd root admin
	./imqsauth -c=example-local.conf permgroupadd root enabled

To create a regular user, you would do the same thing,
except leave out the `permgroupadd root admin` step.

To run the server:

	./imqsauth -c=example-local.conf run

### Running outside docker

The auth service is capable of detecting whether it is running inside or outside of Docker 
upon startup. It leverages the service discovery mechanism in the config service to transparently
rewrite database connection configurations, as well as other serviceconfig utils to detect whether or not
it is inside the auth service.
