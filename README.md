# OAuth 2.0 / OIDC Playground

this is a small golang application, that can be run either locally by running 

```sh
go build main.go
./main
```

or creating a docker-container and running it inside a kubernetes-cluster.

The intention is, that you can use it to connect to any Identity-Provider you like and test/debug the OAuth/OIDC flows with your Provider.

> NOTE:
> This application must not be used in production, it is unsafe since it will display your access-token and does not provide https endpoints.
