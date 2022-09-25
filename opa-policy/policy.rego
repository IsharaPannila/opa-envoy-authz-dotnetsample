package envoy.authz

    import input.attributes.request.http as http_request
    import input.parsed_path

    default allow = false

    allow {
        parsed_path[0] == "health"
        http_request.method == "GET"
    }

    allow {
        print("Found Claims",claims.roles) 
        required_roles[r]
    }


    required_roles[r] {
        perm := role_perms[claims.roles[r]][_]
        perm.method = http_request.method
        perm.path = http_request.path
    }

    claims := payload {
        [_, payload, _] := io.jwt.decode(bearer_token)
    }
  
    bearer_token := t {
        v := http_request.headers.authorization
        startswith(v, "Bearer ")
        t := substring(v, count("Bearer "), -1)
    }

    role_perms = {
        "client.read": [
            {"method": "GET",  "path": "/weatherforecast"},
        ],
        "client.readwrite": [
            {"method": "POST",  "path": "/weatherfeed"},
        ],
    }
