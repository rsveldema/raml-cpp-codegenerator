import argparse
import json
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import yaml
import logging
import functools


from rawl_loader import ExtLoader

from TypeAST import ASTType, ASTMember, ASTNodeEnum, enum_name_map, reset_global_state

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("debug.log"), logging.StreamHandler()],
)

log = logging.getLogger("yaml")

glob_counter = 0
basename = ""

# Set MyLoader as default.
load = functools.partial(yaml.load, Loader=ExtLoader)


def read_raw_yaml(file_path: str) -> dict:
    with open(file_path, "r") as file:
        data = load(file)
    return data


root_file_path: Path = Path("")


def set_root_file_path(input: str):
    global root_file_path
    root_file_path = Path(input).parent


def read_json(file: str) -> dict:
    ix = file.find("#")
    path = None
    if ix != -1:
        path = file[ix + 1 :]
        file = file[0:ix]
    with open(root_file_path.joinpath("schemas").joinpath(file), "r") as f:
        data = json.load(f)

    if path is not None:
        parts = path.strip("/").split("/")
        for p in parts:
            data = data[p]
    return data


def safe_path(elt: str) -> str:
    k = elt.strip("/").replace("/", "_").replace("{", "").replace("}", "")
    if k == "":
        k = "root"
    return k


class Method:
    def __init__(self, name: str, data: dict) -> None:
        self.name = name
        self.data = data
        self.body_type_name: str | None = None
        self.response_type_name: str | None = None
        self.responses: Dict[str, str] = {}


class Endpoint:
    def __init__(self, header_file: str, impl_file: str, elt: str, data: dict) -> None:
        self.header_file = header_file
        self.impl_file = impl_file
        self.path = elt
        self.data = data
        self.methods: List[Method] = []


def get_enum_value_name(value: str) -> str:
    keywords = ["auto", "register", "for", "while", "if", "do", "switch", "case"]

    ret = value.replace("/", "_").replace("-", "_").replace(" ", "_").replace(".", "_")
    ret = ret.replace("'", "").replace('"', "").replace(":", "_")
    if ret[0].isdigit():
        ret = "_" + ret
    if ret in keywords:
        ret = "_" + ret
    return ret


def safe_enum_values(enum_values: List[str]) -> str:
    return ", ".join([f"{i}" for i in [get_enum_value_name(k) for k in enum_values]])


def generate_enum_body(enum_values) -> ASTType:
    ret = ASTType(ASTNodeEnum.ENUM, "enum")
    for value in enum_values:
        value_name = get_enum_value_name(value)
        e = ASTMember(value_name, ASTType(ASTNodeEnum.STRING, "enum_mem"))
        e.value = value
        ret.add_member(e)
    return ret


def generate_type_struct_body(body, props, type_dict) -> ASTType:
    assert isinstance(props, dict)

    global glob_counter
    glob_counter += 1

    ret = ASTType(ASTNodeEnum.OBJECT, "struct")
    ix = 0
    for prop in props:
        prop_body = props[prop]
        if prop.startswith("^(0|([1-9]"):
            prop = 'positive_integer'
        eltType = generate_type_as_single_string(prop_body, type_dict)
        member = ASTMember(str(prop), eltType)

        if "default" in prop_body:
            member.default_value = prop_body['default']

        ret.add_member(member)
        ix += 1
    return ret


def generate_type_allof_or_anyof_body(body, props, type_dict, tt: ASTNodeEnum) -> ASTType:
    assert isinstance(props, list)

    ret = ASTType(tt, "allof") if tt == ASTNodeEnum.ALL_OF else ASTType(tt, "anyof")

    ix = 0
    for prop in props:
        mt = generate_type_as_single_string(prop, type_dict)
        mt.anonymous = True
        ret.add_member(ASTMember(f"_field_{ix}", mt))
        ix += 1
    return ret


def generate_type_struct(body: dict, type_dict: Dict[str, dict]) -> ASTType:
    if "allOf" in body:
        props = body["allOf"]
        return generate_type_allof_or_anyof_body(body, props, type_dict, ASTNodeEnum.ALL_OF)
    elif "anyOf" in body:
        props = body["anyOf"]
        return generate_type_allof_or_anyof_body(body, props, type_dict, ASTNodeEnum.ANY_OF)
    elif "oneOf" in body:
        props = body["oneOf"]
        return generate_oneof(props, type_dict)
    elif "properties" in body:
        props = body["properties"]
        ret = generate_type_struct_body(
            body,
            props,
            type_dict,
        )
        if "patternProperties" in body:
            pattern = body["patternProperties"]
            log.warning("Both patternProperties and properties found, using properties")
            contains_object = None
            for k in pattern:
                elt = pattern[k]
                if "type" in elt and elt["type"] == "object":
                    contains_object = elt
                elif "properties" in elt:
                    contains_object = elt

            if contains_object:
                k = generate_type_pattern_body(
                    pattern,
                    contains_object,
                    type_dict,
                )
                member = ASTMember("WILDCARD", k)
                ret.add_member(member)
        return ret
    elif "patternProperties" in body:
        pattern = body["patternProperties"]
        if "properties" in body:
            log.warning("Both patternProperties and properties found, using patternProperties")
        contains_object = None
        for k in pattern:
            elt = pattern[k]
            if "type" in elt and elt["type"] == "object":
                contains_object = elt
            elif "properties" in elt:
                contains_object = elt
            elif "patternProperties" in elt:
                contains_object = elt["patternProperties"]

        if contains_object:
            return generate_type_pattern_body(
                pattern,
                contains_object,
                type_dict,
            )
        return ASTType(ASTNodeEnum.KEY_VALUE_SET, "kvs")
    else:
        props = {}
        return generate_type_struct_body(
            body,
            props,
            type_dict,
        )


def generate_anyof(anyof, type_dict) -> ASTType:
    # return generate_type_struct(body=anyof, type_dict=type_dict, forwarding_fp=forwarding_fp, ctxt=ctxt)
    props = anyof
    return generate_type_allof_or_anyof_body(anyof, props, type_dict, ASTNodeEnum.ANY_OF)

def generate_allof(allof, type_dict) -> ASTType:
    # return generate_type_struct(body=anyof, type_dict=type_dict, forwarding_fp=forwarding_fp, ctxt=ctxt)
    props = allof
    return generate_type_allof_or_anyof_body(allof, props, type_dict, ASTNodeEnum.ALL_OF)

def generate_type_pattern_body(
                pattern,
                pattern_props,
                type_dict,
            ) -> ASTType:
    """
    Example:
    "patternProperties": {
        "^[a-zA-Z0-9\\-_]+$":{   <--- props
          "type": "object",
    """

    props = pattern_props # pattern_props.get("properties", {})
    if 'type' in props:
        props = pattern_props.get("properties", {})

    assert isinstance(props, dict)
    ret = ASTType(ASTNodeEnum.PATTERN_PROPERTIES, "pattern_props")
    ix = 0
    for prop in props:
        prop_body = props[prop]
        if prop.startswith("^(0|([1-9]"):
            prop = 'positive_integer'
        if prop.startswith("^[a-zA-Z0-9"):
            prop = 'identifier'
        eltType = generate_type_as_single_string(prop_body, type_dict)
        member = ASTMember(str(prop), eltType)

        log.info(f"generate_type_pattern_body: adding member {member.name} of type {eltType.t}")

        ret.add_member(member)
        ix += 1
    return ret

def generate_oneof(oneof, type_dict: Dict[str, dict]) -> ASTType:
    ix = 0
    ret = ASTType(ASTNodeEnum.ONE_OF, "oneof")

    for option in oneof:
        if "pattern" in option:
            t = ASTType(ASTNodeEnum.REG_EX, "regex")
        elif "enum" in option:
            enum_values = option["enum"]
            t = generate_enum_body(enum_values)
        elif "type" in option:
            t = generate_type_as_single_string(option, type_dict)
        elif "$ref" in option:
            ref = option["$ref"]
            data = read_json(ref)
            t = generate_type_as_single_string(data, type_dict)
        elif "format" in option:
            t = builtin_types.get(option["format"], ASTType(ASTNodeEnum.STRING, "fmt"))
        elif "properties" in option:
            body = option
            props = body["properties"]
            t = generate_type_struct_body(body, props, type_dict)
        else:
            # ret += generate_type_as_single_string(opt, type_dict, forwarding_fp)
            raise Exception(f"Unsupported oneOf option: {option}")
        e = ASTMember(f"ix_{ix}", t)
        ret.add_member(e)
        ix += 1
    return ret


builtin_types = {
    "hostname": ASTType(ASTNodeEnum.HOSTNAME, "hostname"),
    "ipv4": ASTType(ASTNodeEnum.IPV4, "ipv4"),
    "ipv6": ASTType(ASTNodeEnum.IPV6, "ipv6"),
}


def generate_type_as_single_string(body, type_dict: Dict[str, dict]) -> ASTType:
    if not body:
        return ASTType(ASTNodeEnum.EMPTY, "empty")

    if isinstance(body, dict):
        if "type" in body:
            type_str = body["type"]
            if isinstance(type_str, str):
                if "{" in type_str:
                    body = type_str

    if isinstance(body, str):
        if body in builtin_types:
            return builtin_types[body]

        if "{" in body:
            k = json.loads(body)
            log.debug(f"parsed str to {k}")
            return generate_type_as_single_string(k, type_dict)

        k = read_json(body)
        log.info(f"parsed loaded file to {k}")
        return generate_type_as_single_string(k, type_dict)

    if isinstance(body, dict):
        if len(body) == 2:
            type = body.get("type", None)
            if isinstance(type, str) and "{" in type and "}" in type:
                return generate_type_as_single_string(type, type_dict)
        if "$ref" in body:
            ref = body["$ref"]
            data = read_json(ref)
            return generate_type_as_single_string(data, type_dict)

    if "anyOf" in body:
        anyof = body["anyOf"]
        assert isinstance(anyof, list)
        return generate_anyof(anyof, type_dict)

    if "format" in body:
        fmt = body["format"]
        if fmt in builtin_types:
            return builtin_types[fmt]
        else:
            return ASTType(ASTNodeEnum.STRING, "format")

    if "not" in body:
        fmt = body["not"]
        return ASTType(ASTNodeEnum.STRING, "not")

    if "minimum" in body and "maximum" in body:
        fmt = body["maximum"]
        return ASTType(ASTNodeEnum.INTEGER, "min")

    if "enum" in body and "type" not in body:
        return generate_enum_body(body["enum"])

    if "type" not in body:
        if "pattern" in body:
            fmt = body["pattern"]
            ret = ASTType(ASTNodeEnum.REG_EX, "regex")
            ret.add_member(ASTMember(fmt, ASTType(ASTNodeEnum.STRING, "regex")))
            return ret

        if "allOf" in body:
            allof = body["allOf"]
            assert isinstance(allof, list)
            return generate_allof(allof, type_dict)
        if "minProperties" in body:
            return ASTType(ASTNodeEnum.EMPTY, "minProperties")
        if "properties" in body:
            ret = generate_type_struct(body, type_dict)
            log.debug(f"generate_type_struct: object type generated: {ret}")
            return ret
        raise RuntimeError(f"generate_type_as_single_string: no type in body: {body}")

    t = body["type"]
    match t:
        case ["integer", "number"]:
            ret = ASTType(ASTNodeEnum.ONE_OF, "oneof_int_num")
            # we generate this one by hand:
            ret.generated_deserializer_already = True
            ret.generated_serializer_already = True
            ret.add_member(ASTMember("__field0", ASTType(ASTNodeEnum.INTEGER, "tuple_int")))
            ret.add_member(ASTMember("__field1", ASTType(ASTNodeEnum.STRING, "tuple_str")))
            return ret
        case ["string", "boolean"]:
            ret = ASTType(ASTNodeEnum.ONE_OF, "oneof_str_bool")
            # we generate this one by hand:
            ret.generated_deserializer_already = True
            ret.generated_serializer_already = True
            ret.add_member(ASTMember("__field0", ASTType(ASTNodeEnum.STRING, "")))
            ret.add_member(ASTMember("__field1", ASTType(ASTNodeEnum.BOOLEAN, "")))
            return ret
        case ["integer", "null"]:
            ret = ASTType(ASTNodeEnum.ONE_OF, "oneof_int_null")
            # we generate this one by hand:
            ret.generated_deserializer_already = True
            ret.generated_serializer_already = True
            ret.add_member(ASTMember("__field0", ASTType(ASTNodeEnum.INTEGER, "")))
            ret.add_member(ASTMember("__field1", ASTType(ASTNodeEnum.NULL, "")))
            return ret
        case ["string", "null"]:
            ret = ASTType(ASTNodeEnum.ONE_OF, "oneof_str_null")
            # we generate this one by hand:
            ret.generated_deserializer_already = True
            ret.generated_serializer_already = True
            ret.add_member(ASTMember("__field0", ASTType(ASTNodeEnum.STRING, "")))
            ret.add_member(ASTMember("__field1", ASTType(ASTNodeEnum.NULL, "")))
            return ret
        case ["null", "string"]:
            ret = ASTType(ASTNodeEnum.ONE_OF, "oneof_null_str")
            # we generate this one by hand:
            ret.generated_deserializer_already = True
            ret.generated_serializer_already = True
            ret.add_member(ASTMember("__field1", ASTType(ASTNodeEnum.NULL, "")))
            ret.add_member(ASTMember("__field0", ASTType(ASTNodeEnum.STRING, "")))
            return ret
        case "object":
            ret = generate_type_struct(body, type_dict)
            log.debug(f"generate_type_struct: object type generated: {ret}")
            return ret
        case "array":
            ret = ASTType(ASTNodeEnum.ARRAY, "array_type")
            elt_type = generate_type_as_single_string(body["items"], type_dict)
            ret.add_member(ASTMember("items", elt_type))
            return ret
        case "string":
            if "enum" in body:
                enum_values = body["enum"]
                return generate_enum_body(enum_values)
            return ASTType(ASTNodeEnum.STRING, "str")
        case "integer":
            return ASTType(ASTNodeEnum.INTEGER, "int")
        case "number":
            return ASTType(ASTNodeEnum.DOUBLE, "dbl")
        case "boolean":
            return ASTType(ASTNodeEnum.BOOLEAN, "bool")
        case "null":
            return ASTType(ASTNodeEnum.NULL, "null")
        case _:
            return generate_type_as_single_string(type_dict[t], type_dict)


def generated_types(
    fp,
    fpc,
    data: dict,
    elt: str,
    type_dict: Dict[str, dict],
    forwarding_fp,
    method: str,
    ep: Endpoint
):
    method_data = Method(method.upper(), data)
    ep.methods.append(method_data)

    # allow deserialization of content body:
    body = data.get("body", None)
    if body is not None:
        assert isinstance(body, dict)
        body_type_name = f"body_{method}"
        method_data.body_type_name = body_type_name

        ast = generate_type_as_single_string(body, type_dict)
        ast.normalize()
        ast.write_types(forwarding_fp, fpc)
        ast.write_serializers(forwarding_fp, fpc)
        ast.write_deserializers(forwarding_fp, fpc)
        fp.write(f"using {body_type_name} = {ast.name};\n")

    responses = data.get("responses", {})
    assert isinstance(responses, dict)
    assert len(responses) > 0, f"No responses defined for {elt}"
    all_replies = ""
    comma = ""
    for code in responses:
        resp = responses[code]
        rc = f"reply_{method}_{code}"
        if resp is None or resp.get("body") is None:
            fp.write(f"using {rc} = http::EmptyObject_{code};\n")
            all_replies += comma + rc
            comma = ", "
            method_data.responses[code] = rc
            continue

        # allow serialization of responses:
        body = resp.get("body", {})
        ast = generate_type_as_single_string(body, type_dict)
        ast.normalize()
        ast.write_types(forwarding_fp, fpc)
        ast.write_serializers(forwarding_fp, fpc)
        ast.write_deserializers(forwarding_fp, fpc)
        fp.write(f"using {rc} = {ast.name};\n")
        all_replies += comma + rc
        comma = ", "
        method_data.responses[code] = rc
    rt = f"response_{method}"
    method_data.response_type_name = rt
    fp.write(f"using {rt} = std::variant<std::monostate, {all_replies}>;\n")

    fp.write(f"static std::string serialize_response(const {rt}& response);\n")
    fpc.write("\n")
    fpc.write(f"std::string Endpoint::serialize_response(const {rt}& response) {{\n")
    fpc.write("	if (std::holds_alternative<std::monostate>(response)) {\n")
    fpc.write('		return "{}";\n')
    fpc.write("	}\n")
    ix = 1
    for code in method_data.responses:
        rc = method_data.responses[code]
        fpc.write(f"	if (response.index() == {ix}) {{\n")
        fpc.write(f"		const auto& r = std::get<{ix}>(response);\n")
        fpc.write("		return serialize(r);\n")
        fpc.write("	}\n")
        ix += 1
    fpc.write('	return "";\n')
    fpc.write("}\n")
    fpc.write("\n")

    fp.write(f"static http::StatusCode get_status_code(const {rt}& response);\n")
    fpc.write(f"http::StatusCode Endpoint::get_status_code(const {rt}& response) {{\n")
    fpc.write("	if (std::holds_alternative<std::monostate>(response)) {\n")
    fpc.write("		return http::StatusCode::INTERNAL_SERVER_ERROR;\n")
    fpc.write("	}\n")
    ix = 1
    for code in method_data.responses:
        rc = method_data.responses[code]
        fpc.write(f"	if (response.index() == {ix}) {{\n")
        fpc.write(f"		return static_cast<http::StatusCode>({code});\n")
        fpc.write("	}\n")
        ix += 1
    fpc.write("	return http::StatusCode::INTERNAL_SERVER_ERROR;\n")
    fpc.write("}\n")


def is_method_name(p: str) -> bool:
    methods = ["get", "post", "put", "delete", "patch", "head", "options", "trace"]
    return p.lower() in methods


def generate_endpoint(
    elt: str, data: dict, all_endpoints: List[Endpoint], type_dict: Dict[str, dict], base_uri: str
):
    log.info(f"Generating endpoint for {elt}")

    reset_global_state()

    forwarding_fpname = f"gen/forward_decls_{basename}_{safe_path(elt)}.hpp"
    forwarding_fp = open(forwarding_fpname, "w")
    #forwarding_fp.write("#pragma once\n\n")
    forwarding_fp.write("\n")
    header_filename = f"gen/{basename}_{safe_path(elt)}.hpp"
    impl_filename = f"gen/{basename}_{safe_path(elt)}.cpp"
    ep = Endpoint(header_filename, impl_filename, elt, data)
    all_endpoints.append(ep)

    fpc = open(impl_filename, "w")
    fpc.write(f'#include "{header_filename}"\n')

    fp = open(header_filename, "w")
    fp.write("#pragma once\n\n")
    fp.write("#include <slogger/ILogger.hpp>\n")
    fp.write("#include <http/base_endpoint.hpp>\n\n")
    fp.write("#include <string>\n")
    fp.write("#include <map>\n")
    fp.write("#include <vector>\n")
    fp.write("#include <optional>\n")
    fp.write("#include <variant>\n")
    fp.write("#include <fstream>\n")
    fp.write("#include <stdexcept>\n")
    fp.write("#include <nlohmann/json.hpp>\n")
    fp.write("using json = nlohmann::json;\n")

    fp.write(f"// Endpoint: {elt}\n")
    fp.write(f"// description: {data.get('description', '')}\n")

    fp.write(f"namespace {basename}::{safe_path(elt)}\n {{\n")
    fpc.write(f"namespace {basename}::{safe_path(elt)}\n {{\n")

    fp.write("class Endpoint : public http::BaseEndpoint {\n")
    fp.write("public:\n")
    fp.write(f'static constexpr const char* BASE_URI = "{base_uri.replace('{version}', 'v1.3')}";\n')

    fp.write("#include <http/base_serializers.hpp>\n")
    fp.write(f"#include <{forwarding_fpname}>\n")
    fp.write("\n")

    for p in data:
        p = p.lower()
        if is_method_name(p):
            generated_types(fp, fpc, data[p], elt, type_dict, forwarding_fp, p, ep)
    fp.write("\n")

    fp.write(
        "	Endpoint(logging::ILogger& logger, const std::shared_ptr<model::Node>& model) : m_logger(logger), m_model(model) {\n"
    )
    fp.write("	}\n")
    fp.write("	logging::ILogger& m_logger;\n")
    fp.write("	std::shared_ptr<model::Node> m_model;\n")
    fp.write("\n")
    fp.write("	logging::ILogger& get_logger() const { return m_logger; }\n")
    fp.write("\n")
    fp.write(
        '	std::string get_endpoint_path() const override { return "' + elt + '"; }\n'
    )
    fp.write("\n")

    for m in ep.methods:
        p = m.name.lower()
        fp.write("\n")

        fp.write(f"	using reply_func_{p}_t = std::function<void({m.response_type_name})>;\n")

        if m.body_type_name is not None:
            fp.write(
                f"	void handle_{p}([[maybe_unused]] const http::URLParameters& params, [[maybe_unused]] const {m.body_type_name}& body, reply_func_{p}_t reply);\n"
            )
        else:
            fp.write(
                f"	void handle_{p}([[maybe_unused]] const http::URLParameters& params, reply_func_{p}_t reply);\n"
            )

        fp.write("\n")

        fp.write(
            f"void get_reply_{p}(const std::string& endpoint, const std::string& payload, const http::URLParameters& params, http::reply_handler_t handler);\n"
        )
        fpc.write(
            f"void Endpoint::get_reply_{p}(const std::string& endpoint, const std::string& payload, const http::URLParameters& params, http::reply_handler_t handler) {{\n"
        )
        fpc.write(
            f'		fprintf(stderr, "deserialize {elt} - %s, %s\\n", endpoint.c_str(), payload.c_str());\n'
        )

        body = ""

        if m.body_type_name is not None:
            fpc.write(f"		{m.body_type_name} body;\n")
            fpc.write("		json data;\n")
            fpc.write("	    try {\n")
            fpc.write("	       data = json::parse(payload);\n")
            fpc.write("	    } catch (json::parse_error& ex) {\n")
            fpc.write(
                '			handler(http::HandlerResult{http::create_json_error_msg(std::format("json structure not ok: {}", ex.what())), http::StatusCode::BAD_REQUEST});\n'
            )
            fpc.write("	        return;\n")
            fpc.write("	    }\n")

            fpc.write("		try {\n")
            fpc.write("			deserialize(body, data);\n")
            fpc.write("		} catch (ParseError& e) {\n")
            fpc.write(
                '			handler(http::HandlerResult{http::create_json_error_msg("json structure not ok"), http::StatusCode::BAD_REQUEST});\n'
            )
            fpc.write("	        return;\n")
            fpc.write("		}\n")
            body = "body,"
        else:
            fpc.write("		// No body for this method\n")
            body = ""

        fpc.write(f"		handle_{p}(params, {body} [handler](const {m.response_type_name}& reply_payload) {{\n")
        fpc.write("          auto hr = http::HandlerResult{serialize_response(reply_payload), get_status_code(reply_payload)};\n")
        fpc.write("          handler(hr);\n")
        fpc.write("		});\n")
        fpc.write("	}\n")

    fp.write("}; // Endpoint class\n")
    fp.write("} // namespace\n")
    fp.close()

    fpc.write("} // namespace\n")
    fpc.close()

    forwarding_fp.close()

    # Go recursive:
    for p in data:
        if p.startswith("/"):
            generate_endpoint(elt + p, data[p], all_endpoints, type_dict, base_uri)


def generate_type_list(data: dict, type_dict: Dict[str, dict]):
    log.info("Generating types")
    for elt in data:
        # log.info(f" Type: {elt} = {data[elt]}")
        type_dict[elt] = data[elt]

def generate_all_endpoints_header(all_endpoints: List[Endpoint]):
    fp = open(f"gen/all_endpoints-{basename}.hpp", "w")
    fp.write("#pragma once\n\n")
    fp.write("// Auto-generated file including all endpoint headers\n\n")
    fp.write("#include <http/base_endpoint.hpp>\n\n")
    for f in all_endpoints:
        fp.write(f'#include "{f.header_file}"\n')

    fp.write("\n")
    fp.write(f"namespace {basename} {{\n")
    fp.write("class AllEndpoints {\n")
    fp.write("public:\n")
    for endpoint in all_endpoints:
        elt = safe_path(endpoint.path)
        fp.write(f"    {elt}::Endpoint endpoint_{elt};\n")

    fp.write(
        "AllEndpoints(logging::ILogger& logger, const std::shared_ptr<model::Node>& model)\n"
    )
    comma = ":"
    for endpoint in all_endpoints:
        elt = safe_path(endpoint.path)
        fp.write(f"   {comma} endpoint_{elt}(logger, model)\n")
        comma = ", "
    fp.write("{}\n")
    fp.write("\n")

    fp.write("	void register_endpoints(http::HttpServer& http_server);\n")
    fp.write("};\n")
    fp.write(f"}} // namespace {basename}\n")
    fp.close()


def generate_all_endpoints_impl(all_endpoints: List[Endpoint], base_uri:str):
    fpc = open(f"gen/all_endpoints-{basename}.cpp", "w")
    fpc.write(f"#include <gen/all_endpoints-{basename}.hpp>\n")
    for f in all_endpoints:
        fpc.write(f'#include "{f.impl_file}"\n')
    fpc.write(f"namespace {basename} {{\n")
    fpc.write("void AllEndpoints::register_endpoints(http::HttpServer& http_server) {\n")
    for endpoint in all_endpoints:
        elt = safe_path(endpoint.path)
        for method_data in endpoint.methods:
            method = method_data.name
            fpc.write(
                f'		 http_server.register_endpoint_handler("{base_uri}{endpoint.path}", http::HttpMethod::{method},\n'
            )
            fpc.write(
                "			[this](const std::string& endpoint, const std::string& payload, const http::URLParameters& params, http::reply_handler_t reply_handler) {\n"
            )
            fpc.write(
                "				endpoint_"
                + elt
                + ".get_reply_"
                + method.lower()
                + "(endpoint, payload, params, reply_handler);\n"
            )
            fpc.write("			});\n\n")
    fpc.write("}\n")
    fpc.write(f"}} // namespace {basename}\n")
    fpc.close()


def main():
    parser = argparse.ArgumentParser(
        prog="RAWL Codegen",
        description="Read nmos specification YAML files with include and generate code for it",
        epilog="Text at the bottom of help",
    )
    parser.add_argument("-v", "--version", action="version", version="ProgramName 1.0")
    parser.add_argument("--input", help="Input file")
    args = parser.parse_args()

    input = args.input
    base_uri = ""
    set_root_file_path(input)
    log.info(f"Input file: {input}")

    global basename
    basename = Path(input).name
    basename = basename[0 : basename.find(".")]

    data = read_raw_yaml(input)
    # print(f"JSON data: {data}")
    all_endpoints: List[Endpoint] = []
    type_dict: Dict[str, dict] = {}
    for elt in data:
        global glob_counter
        glob_counter = 0

        if elt == "types":
            generate_type_list(data[elt], type_dict)
        if elt == "baseUri":
            baseuri_str = data[elt]
            log.info(f"BASE URI = {baseuri_str}")
            #  http://api.example.com/x-nmos/node/{version}
            url = urlparse(baseuri_str)
            base_uri = url.path

        if elt.startswith("/"):
            generate_endpoint(elt, data[elt], all_endpoints, type_dict, base_uri)
        else:
            log.warning(f"Skipping non-endpoint top-level element: {elt}")

    log.info("generating files")

    generate_all_endpoints_header(all_endpoints)
    generate_all_endpoints_impl(all_endpoints, base_uri)



main()
log.info("Code generation finished!")