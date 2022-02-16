# Cloud Run Proxy

Cloud Run Proxy is a small proxy to assist in authenticating as an end-user to
Google Cloud Run. It leverages Cloud Run's existing Cloud IAM integration to
handle access.

By default, users with the Cloud Run Invoker role (`roles/run.invoker`) have
permission to call services. This is demonstrated multiple times in the Cloud
Run documentation:

```sh
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" https://my-service.a.run.app/
```

This works great for stateless API calls, but what if you have a
semi-long-running service or a web interface to access via the browser? This is
where **Cloud Run Proxy** can help!

Cloud Run Proxy runs a localhost proxy that behaves exactly as if you're calling
the URL directly, except that it adds your local user's authentication info
(from gcloud).

If you're familiar with the Cloud SQL Proxy, it's like that, but for Cloud Run.

**Cloud Run Proxy is not an officially supported Google product.**

## Usage

Note: you must install and authenticated to the [Google Cloud
SDK](https://cloud.google.com/sdk) (gcloud) for the proxy to pull your
authentication token. You local user must also have Cloud Run Invoker
permissions on the target service.

1.  Install the proxy:

    ```sh
    go get github.com/GoogleCloudPlatform/cloud-run-proxy
    ```

1.  Start the proxy:

    ```sh
    cloud-run-proxy -host https://my-service.a.run.app
    ```

1.  Point your browser or `curl` at http://localhost:8080!


## Options

Change the local bind address:

```sh
cloud-run-proxy -bind "127.0.0.1:1234"
```

Obligatory security note: do not bind to 0.0.0.0 or your public IP. Anyone on
your network would then be able to access your service unauthenticated. Always
bind to a loopback.

Override the token (useful if you don't have gcloud installed):

```sh
cloud-run-proxy -token "yc..."
```

Specify a custom audience:

```sh
cloud-run-proxy -audience "https://my-service-daga283.run.app"
```

Note: when running on Compute Engine or other services with a metadata service, the audience defaults to the host URL. If you are accessing your Cloud Run service through a load balancer with a vanity domain, you must specify the audience value as the non-vanity URL of your service:

```sh
cloud-run-proxy -host "https://custom-domain.com" -audience "https://my-service-daga283.run.app"
```
