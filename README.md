# raml-cpp-codegenerator

A code generator for RAML files as used by the NMOS specifications (https://specs.amwa.tv/nmos/,
https://github.com/AMWA-TV/nmos).

The idea:

    <RAML file>  --> codegenerator ---> C++ code

Dependencies
======================

The codegenerator is written in Python, so you'll need python 3.12+
See 'requirements.txt' for requirements.

You'll need a logging library and a C++ capable httpserver to bind the generated code to.
I'm using a web server based on iuring.

Invocation
================

```bash
     python raml-cpp-codegenerator/main.py --input ConnectionAPI.raml
```
will generate a bunch of files in the working directory.

To integrate the code generator in your build system, I suggest something like the following (assuming you've added this as a git submodule):

```cmake
add_custom_command(
    OUTPUT gen/all_endpoints-ConnectionAPI.hpp
    COMMAND mkdir -p gen
    COMMAND python ${PROJECT_SOURCE_DIR}/raml-cpp-codegenerator /main.py --input ${PROJECT_SOURCE_DIR}/is-05/APIs/ConnectionAPI.raml
    DEPENDS is-05/APIs/ConnectionAPI.raml
    DEPENDS ${PROJECT_SOURCE_DIR}/raml-cpp-codegenerator/main.py
    DEPENDS ${PROJECT_SOURCE_DIR}/raml-cpp-codegenerator/TypeAST.py
)
```


Generated code
=================

For each RAML endpoint we
- generate a C++ class that represents the endpoint
- generate a serializer/deserializer from/to JSON
  to access the arguments and/or the return values from and endpoint.


For example, given the following exerpt:

```yaml
types:
  Sources: !include schemas/sources.json
/sources:
  displayName: Sources
  get:
    description: List Sources
    responses:
      200:
        body:
          type: "object"
          properties:
            foo:
                type: "string"
      400:
        body:
          type: "object"
          properties:
            bar:
                type: "string"
```

we generate a class and supporting code.
Below an excerpt of the relevant parts:

```C++
namespace sources {
    class Endpoint {
        class reply_get_200 {
            std::string foo;
        };
        class reply_get_400 {
            std::string bar;
        };
        using response_get =    std::variant<std::monostate,
            reply_get_200, reply_get_400>;

        using reply_func_get_t = std::function<void(response_get)>;

        void handle_get([[maybe_unused]] const http::URLParameters& params, reply_func_get_t reply);

        // ... more support methods generated...
    };
}
```

To create a complete program the 'handle_get(reply_handler_t)' function is then to be implemented by you. The code generator takes care of packing the objects returned to from JSON.

For example, you would do sth like:

```C++
namespace sources {
    void Endpoint::handle_get([[maybe_unused]] const http::URLParameters& params, reply_func_get_t reply) {
        reply_get_200 ok {
            .foo = 123;
        };
        reply(ok);
}
}
```

To integrate the above into a http-server, we generate an extra class that holds all endpoint classes we've generated:

```c++
#include <all_endpoints-NodeAPI.hpp>
```

contains:

```c++

class AllEndpoints {
public:
    sources::Endpoint endpoint_sources;
    ...

    void register_endpoints(http::HttpServer& http_server) {
        http_server.register_endpoint_handler("<endpoint/path>",
            http::HttpMethod::GET,
            [this](const std::string& endpoint,
            const std::string& payload, const http::URLParameters& params,
            http::reply_handler_t reply_handler) {
        // code generated here that calls
        // generated endpoint handler
        // from above
                        });
        // and the same for all other endpoints...
};
```


Some details
---------------

- OpenAPI/RAML patterns like:
```yaml
    type: object
    properties:
        ...
```

    translate to a class

- OpenAPI/RAML 'oneOf' translates to a std::variant:

```yaml
  "oneOf": [
    {
      "type": "object",
      "description": "Obj1",
      "title": "object 1 schema",
      "properties": { ... },
    },  {
      "type": "object",
      "description": "Obj2",
      "title": "object 2 schema",
      "properties": { ... },
    }
  ]
```

becomes:

```c++
class obj1 { ... };
class obj2 { ... }
using oneof = std::variant<obj1, obj2>
```

- anyof/allof translate to classes with all properties merged.
- pattern rules becomes a map of variants:

```yaml
{

  "type": "object",
  "additionalPropertes": false,
  "patternProperties": {
    "^[a-zA-Z0-9\\-_]+$": {
            ...obj 1...
            ...obj 2...
    }
}
```

```c++
using patterntype = std::map<std::string, std::vector<std::variant<obj1,obj2>>>;
```

again, the code generator takes care of serialation to/from json.
You, the user of the code generator have to add the business logic of adding/retrieving data from the patterntype above.