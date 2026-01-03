from enum import Enum
import logging
from typing import Dict, List

log = logging.getLogger("yaml")

MAX_MEMBERS_BEFORE_SHORTENING_STRUCT_NAMES = 3
MAX_TYPE_NAME_LENGTH = 32


def shorten(s):
    """
    shorten foo_bar to fb

    :param s: Description
    """
    ix = s.find("_")
    if ix > 0 and ((ix + 1) < len(s)):
        s = s[0] + s[ix + 1]

    s = s.replace(":", "")

    if s == "stdstring":
        s = "string"
    if s == "wwwRegEx":
        s = "regEx"

    if len(s) > MAX_TYPE_NAME_LENGTH:
        s = s[0:MAX_TYPE_NAME_LENGTH]

    if s.endswith("_"):
        s = s[0 : len(s) - 1]

    return s


class ASTNodeEnum(Enum):
    EMPTY = "EMPTY"
    INTEGER = "INTEGER"
    STRING = "STRING"
    DOUBLE = "DOUBLE"
    BOOLEAN = "BOOLEAN"
    OBJECT = "OBJECT"
    ARRAY = "ARRAY"
    ANY_OF = "ANY_OF"
    ONE_OF = "ONE_OF"
    ALL_OF = "ALL_OF"
    PATTERN_PROPERTIES = "PATTERN_PROPERTIES"
    ENUM = "ENUM"
    ENUM_ENTRY = "ENUM_ENTRY"
    REG_EX = "REG_EX"
    KEY_VALUE_SET = "KEY_VALUE_SET"
    NULL = ("NULL",)
    HOSTNAME = "HOSTNAME"
    IPV4 = "IPV4"
    IPV6 = "IPV6"


class ASTMember:
    def __init__(self, name: str, type: "ASTType"):
        # self.name is the C++ name, might've been made unique
        self.name = name
        # self.orig_name is the one we're read from the rawl
        self.orig_name = name
        self.type = type
        self.value = None
        self.parent: ASTType | None = None
        self.default_value = None

    def equals(self, other: "ASTMember") -> bool:
        if self.name != other.name:
            return False
        return self.type.equals(other.type)


enum_name_map: Dict[str, int] = {}
global_counter = 0
unique_enums: List["ASTType"] = []
unique_objects: List["ASTType"] = []
unique_anyofs: List["ASTType"] = []
unique_allofs: List["ASTType"] = []
unique_patterns: List["ASTType"] = []
unique_oneofs: List["ASTType"] = []
unique_arrays: List["ASTType"] = []


def reset_global_state():
    global glob_counter
    glob_counter = 0
    enum_name_map.clear()
    unique_enums.clear()
    unique_objects.clear()
    unique_anyofs.clear()
    unique_allofs.clear()
    unique_patterns.clear()
    unique_oneofs.clear()
    unique_arrays.clear()


def register_unique_enum(t: "ASTType") -> "ASTType":
    assert t.t == ASTNodeEnum.ENUM
    for uniq in unique_enums:
        if uniq.equals(t):
            return uniq
    unique_enums.append(t)
    t.give_enum_a_unique_name()
    return t


def register_unique_object(t: "ASTType") -> "ASTType":
    assert t.t == ASTNodeEnum.OBJECT
    for uniq in unique_objects:
        if uniq.equals(t):
            return uniq
    unique_objects.append(t)
    return t


def register_unique_anyof(t: "ASTType") -> "ASTType":
    assert t.t == ASTNodeEnum.ANY_OF
    for uniq in unique_anyofs:
        if uniq.equals(t):
            return uniq
    unique_anyofs.append(t)
    return t


def register_unique_allof(t: "ASTType") -> "ASTType":
    assert t.t == ASTNodeEnum.ALL_OF
    for uniq in unique_allofs:
        if uniq.equals(t):
            return uniq
    unique_allofs.append(t)
    return t


def register_unique_pattern(t: "ASTType") -> "ASTType":
    assert t.t == ASTNodeEnum.PATTERN_PROPERTIES
    for uniq in unique_patterns:
        if uniq.equals(t):
            return uniq
    unique_patterns.append(t)
    return t


def register_unique_oneof(t: "ASTType") -> "ASTType":
    assert t.t == ASTNodeEnum.ONE_OF
    for uniq in unique_oneofs:
        if uniq.equals(t):
            return uniq
    unique_oneofs.append(t)
    return t


def register_unique_array(t: "ASTType") -> "ASTType":
    assert t.t == ASTNodeEnum.ARRAY
    for uniq in unique_arrays:
        if uniq.equals(t):
            return uniq
    unique_arrays.append(t)
    return t


def generate_type_name(t: ASTNodeEnum, prefix: str) -> str:
    match t:
        case ASTNodeEnum.ARRAY:
            global global_counter
            global_counter += 1
            c = global_counter
            return f"array_{c}"
        case ASTNodeEnum.EMPTY:
            return "http::EmptyObject"
        case ASTNodeEnum.INTEGER:
            return "int64_t"
        case ASTNodeEnum.STRING:
            return "std::string"
        case ASTNodeEnum.DOUBLE:
            return "double"
        case ASTNodeEnum.BOOLEAN:
            return "bool"
        case ASTNodeEnum.NULL:
            return "http::null_t"
        case ASTNodeEnum.KEY_VALUE_SET:
            return "http::KeyValueSet"
        case ASTNodeEnum.REG_EX:
            return "http::RegEx"
        case ASTNodeEnum.HOSTNAME:
            return "http::hostname_t"
        case ASTNodeEnum.IPV4:
            return "http::ipv4_t"
        case ASTNodeEnum.IPV6:
            return "http::ipv6_t"
        case _:
            """
            k = f"{prefix}_{str(t.name)}"
            if k in enum_name_map:
                enum_name_map[k] += 1
                k = f"{prefix}_{str(t.name)}_{enum_name_map[k]}"
            else:
                enum_name_map[k] = 1
            return k
            """
            return t.name


def value_to_c(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return f"{v}"


class ASTType:
    def __init__(self, t: ASTNodeEnum, prefix: str):
        self.t = t
        self.prefix = prefix
        self.name = generate_type_name(t, prefix)
        self.members: List[ASTMember] = []
        self.generated_type_already = False
        self.generated_serializer_already = False
        self.generated_deserializer_already = False
        self.assigned_new_name = False
        self.anonymous = False

    def equals(self, other: "ASTType") -> bool:
        if self.t != other.t:
            return False
        if len(self.members) != len(other.members):
            return False
        for i in range(len(self.members)):
            if not self.members[i].equals(other.members[i]):
                return False
        return True

    def add_member(self, m: ASTMember):
        m.parent = self
        self.members.append(m)

    def compute_new_name(self, from_name: bool):
        if self.assigned_new_name:
            return

        self.assigned_new_name = True
        k = self.prefix + "_"

        if len(self.members) == 0:
            k += "empty_obj"

        if not from_name and self.t != ASTNodeEnum.ARRAY:
            if len(self.members) > 0 and not self.members[0].name.startswith("_field"):
                from_name = True

        sep = ""
        for elt in self.members:
            elt.type.flatten()

            if from_name:
                if len(self.members) < MAX_MEMBERS_BEFORE_SHORTENING_STRUCT_NAMES:
                    k += sep + shorten(elt.name)
                    sep = "_"
                else:
                    k += elt.name[0]
            else:
                if len(self.members) < MAX_MEMBERS_BEFORE_SHORTENING_STRUCT_NAMES:
                    k += sep + shorten(elt.type.name)
                    sep = "_"
                else:
                    k += elt.type.name[0]

        if k.endswith("_"):
            k = k[0 : len(k) - 1]

        if len(k) > MAX_TYPE_NAME_LENGTH:
            k = k[0:MAX_TYPE_NAME_LENGTH]

        if k in enum_name_map:
            enum_name_map[k] += 1
            k = f"{k}_{enum_name_map[k]}"
        else:
            enum_name_map[k] = 1

        self.name = k

    def normalize_obj(self):
        self.compute_new_name(from_name=True)

    def normalize_array(self):
        for elt in self.members:
            elt.type.flatten()
        self.compute_new_name(from_name=False)

    def normalize_one_of(self):
        for elt in self.members:
            elt.type.flatten()
        self.compute_new_name(from_name=False)

    def normalize_pattern(self):
        for elt in self.members:
            elt.type.flatten()
        # self.single_inline()
        self.compute_new_name(from_name=False)

    def single_inline(self):
        log.info("inlining: " + self.name)
        i = 0
        new_members = []
        for p in self.members:
            if p.type.t == ASTNodeEnum.ANY_OF:
                if p.type.anonymous:
                    new_members.extend(p.type.members)
                    continue
            # if p.type.t == ASTNodeEnum.PATTERN_PROPERTIES:
            #    if p.type.anonymous:
            #        new_members.extend(p.type.members)
            #        continue
            if p.type.t == ASTNodeEnum.ALL_OF:
                if p.type.anonymous:
                    new_members.extend(p.type.members)
                    continue
            if p.type.t == ASTNodeEnum.OBJECT:
                if p.type.anonymous:
                    new_members.extend(p.type.members)
                    continue
            new_members.append(p)
        self.members = new_members

    def normalize_any_of(self):
        for elt in self.members:
            elt.type.flatten()
        self.single_inline()
        self.compute_new_name(from_name=False)

    def normalize_all_of(self):
        for elt in self.members:
            elt.type.flatten()
        self.single_inline()
        self.compute_new_name(from_name=False)

    def normalize_enum(self):
        pass

    def give_enum_a_unique_name(self):
        enum_name = "enum_"
        sep = ""
        for elt in self.members:
            if len(self.members) < MAX_MEMBERS_BEFORE_SHORTENING_STRUCT_NAMES:
                enum_name += sep + shorten(elt.name)
                sep = "_"
            else:
                enum_name += elt.name[0]

        if enum_name.endswith("_"):
            enum_name = enum_name[0 : len(enum_name) - 1]

        if enum_name in enum_name_map:
            enum_name_map[enum_name] += 1
            enum_name = f"{enum_name}_{enum_name_map[enum_name]}"
        else:
            enum_name_map[enum_name] = 1
        self.name = enum_name

    def fix_members_with_same_name_different_types(self):
        for i in range(0, len(self.members)):
            conflicted = False
            m1 = self.members[i]
            m1.type.fix_members_with_same_name_different_types()

            # in the is-8 RAWL there is a 'action:' property name...
            m1.name = m1.name.replace(":", "")

            for k in range(i + 1, len(self.members)):
                m2 = self.members[k]
                if m1.name == m2.name:
                    assert m2.parent is not None
                    m2.name = m2.parent.name + "_" + m2.name
                    conflicted = True
            if conflicted:
                assert m1.parent is not None
                m1.name = m1.parent.name + "_" + m1.name

    def remove_duplicate_members(self):
        i = 0
        while i < len(self.members):
            m1 = self.members[i]
            m1.type.remove_duplicate_members()

            k = i + 1
            while k < len(self.members):
                m2 = self.members[k]
                if m1.equals(m2):
                    log.info(f"deleting duplicate member {m1.name} / {m1.orig_name}")
                    del self.members[k]
                    continue
                k += 1
            i += 1

    def flatten(self):
        match self.t:
            case ASTNodeEnum.OBJECT:
                self.normalize_obj()
            case ASTNodeEnum.ARRAY:
                self.normalize_array()
            case ASTNodeEnum.ANY_OF:
                self.normalize_any_of()
            case ASTNodeEnum.PATTERN_PROPERTIES:
                self.normalize_pattern()
            case ASTNodeEnum.ONE_OF:
                self.normalize_one_of()
            case ASTNodeEnum.ALL_OF:
                self.normalize_all_of()
            case ASTNodeEnum.ENUM:
                self.normalize_enum()
            case _:
                pass

    def remove_duplicate_types(self) -> "ASTType":
        for m in self.members:
            m.type = m.type.remove_duplicate_types()

        if self.t == ASTNodeEnum.ENUM:
            return register_unique_enum(self)
        if self.t == ASTNodeEnum.OBJECT:
            return register_unique_object(self)
        if self.t == ASTNodeEnum.ANY_OF:
            return register_unique_anyof(self)
        if self.t == ASTNodeEnum.ALL_OF:
            return register_unique_allof(self)
        if self.t == ASTNodeEnum.PATTERN_PROPERTIES:
            return register_unique_pattern(self)
        if self.t == ASTNodeEnum.ONE_OF:
            return register_unique_oneof(self)
        if self.t == ASTNodeEnum.ARRAY:
            return register_unique_array(self)
        return self

    def normalize(self) -> "ASTType":
        self.flatten()
        if self.t == ASTNodeEnum.ALL_OF:
            print(self)

        self.remove_duplicate_members()
        self.fix_members_with_same_name_different_types()
        ret = self.remove_duplicate_types()
        return ret

    def generate_enum(self, fp, fpc):
        fp.write(f"enum class {self.name} {{\n")
        comma = ""
        for e in self.members:
            fp.write(f"\t{comma} e_{e.name}\n")
            comma = ","
        fp.write("};\n\n")

    def generate_obj(self, fp, fpc):
        for elt in self.members:
            elt.type.write_types(fp, fpc)

        fp.write(f"struct {self.name} {{\n")
        for elt in self.members:
            init = ""
            if elt.default_value != None:
                init = value_to_c(elt.default_value)
                fp.write(
                    f"\t{elt.type.name} _{elt.name} = {init}; // {elt.orig_name}\n"
                )
            else:
                fp.write(
                    f"\tstd::optional<{elt.type.name}> _{elt.name};  // {elt.orig_name}\n"
                )

        fp.write(f"}}; // {self.name}\n\n")

    def generate_array(self, fp, fpc):
        self.members[0].type.write_types(fp, fpc)
        elts = self.members[0].type.name
        fp.write(f"using {self.name} = std::vector<{elts}>;\n")

    def generate_anyof(self, fp, fpc):
        for elt in self.members:
            elt.type.write_types(fp, fpc)

        fp.write(f"struct {self.name} {{\n")
        for elt in self.members:
            fp.write(
                f"\tstd::optional<{elt.type.name}> _{elt.name}; // {elt.orig_name}\n"
            )
        fp.write(f"}}; // {self.name}\n\n")

    def generate_pattern(self, fp, fpc):
        elt_names = ""
        comma = ""
        for elt in self.members:
            elt.type.write_types(fp, fpc)
            elt_names += f"{comma}{elt.type.name}"
            comma = ", "

        fp.write(
            f"using {self.name} = std::map<std::string, std::vector<std::variant<{elt_names}>>>;\n"
        )

    def generate_allof(self, fp, fpc):
        for elt in self.members:
            elt.type.write_types(fp, fpc)

        fp.write(f"struct {self.name} {{\n")
        for elt in self.members:
            fp.write(f"\t{elt.type.name} _{elt.name};  // {elt.orig_name}\n")
        fp.write(f"}}; // {self.name}\n\n")

    def generate_oneof(self, fp, fpc):
        for elt in self.members:
            elt.type.write_types(fp, fpc)

        comma = ""
        fp.write(f"using {self.name} = std::variant<")
        for elts in self.members:
            fp.write(f"{comma}{elts.type.name}")
            comma = ", "
        fp.write(">;\n")

    def write_types(self, fp, fpc):
        if self.generated_type_already:
            return
        self.generated_type_already = True
        match self.t:
            case ASTNodeEnum.OBJECT:
                self.generate_obj(fp, fpc)
            case ASTNodeEnum.ARRAY:
                self.generate_array(fp, fpc)
            case ASTNodeEnum.ANY_OF:
                self.generate_anyof(fp, fpc)
            case ASTNodeEnum.PATTERN_PROPERTIES:
                self.generate_pattern(fp, fpc)
            case ASTNodeEnum.ONE_OF:
                self.generate_oneof(fp, fpc)
            case ASTNodeEnum.ALL_OF:
                self.generate_allof(fp, fpc)
            case ASTNodeEnum.ENUM:
                self.generate_enum(fp, fpc)
            case ASTNodeEnum.ENUM_ENTRY:
                raise RuntimeError("unhandled")

    def is_inline(self):
        return self.members[0].name.startswith("_field_")

    def _generic_serialize(self, fp, fpc):
        if len(self.members) == 0:
            fp.write(f"static std::string serialize(const {self.name}& );\n")
            fpc.write(f"std::string Endpoint::serialize(const {self.name}& ) {{\n")
            fpc.write("  // type has no members\n")
            fpc.write('  return "{}";\n')
            fpc.write("}\n")
            fpc.write("\n")
            return

        for elt in self.members:
            elt.type.write_serializers(fp, fpc)

        fp.write(f"static std::string serialize(const {self.name}& obj);\n")
        fpc.write(f"std::string Endpoint::serialize(const {self.name}& obj) {{\n")

        fpc.write("  std::string ret;\n")
        fpc.write("  std::string comma;\n")

        if self.is_inline():
            for elt in self.members:
                fpc.write(
                    f'  if (const auto k = serialize(obj._{elt.name}); k != "") {{\n'
                )
                fpc.write("     ret += comma;\n")
                fpc.write('     comma = ", ";\n')
                fpc.write(f"     ret += k;\n")
                fpc.write("  }\n")
        else:
            fpc.write('  ret += "{";\n')
            for elt in self.members:
                fpc.write(
                    f'  if (const auto k = serialize(obj._{elt.name}); k != "") {{\n'
                )
                fpc.write("     ret += comma;\n")
                fpc.write('     comma = ", ";\n')
                fpc.write(f'     ret += "\\"{elt.orig_name}\\":" + k;\n')
                fpc.write("  }\n")
            fpc.write('  ret += "}";\n')
        fpc.write("  return ret;\n")
        fpc.write("}\n")
        fpc.write("\n")

    def generate_obj_serializer(self, fp, fpc):
        self._generic_serialize(fp, fpc)

    def generate_allof_serializer(self, fp, fpc):
        self._generic_serialize(fp, fpc)

    def generate_anyof_serializer(self, fp, fpc):
        self._generic_serialize(fp, fpc)

    def generate_pattern_serializer(self, fp, fpc):
        for elt in self.members:
            elt.type.write_serializers(fp, fpc)

        fp.write(f"static std::string serialize(const {self.name}& map);\n")
        fpc.write(f"std::string Endpoint::serialize(const {self.name}& map) {{\n")
        fpc.write('  std::string ret = "{";\n')
        fpc.write('  const char* comma = "";\n')
        fpc.write("  for (const auto& [key, values] : map) {\n")
        fpc.write("    ret += comma;\n")
        fpc.write('    ret += "\\""+key+"\\":{";\n')
        fpc.write('    const char* comma2 = "";\n')
        fpc.write("    [[maybe_unused]] int ix = 0;\n")
        fpc.write("    for (const auto& val : values) {\n")
        fpc.write("      ret += comma2;\n")
        ix = 0
        fpc.write("      switch (val.index()) {\n")
        for elt in self.members:
            fpc.write(f"      case {ix}: {{\n")
            fpc.write(
                f"         const auto val_str = serialize(std::get<{ix}>(val));\n"
            )
            if elt.name == "positive_integer":
                fpc.write(
                    f'         ret += "\\"" + std::to_string(ix++) + "\\":" + val_str;\n'
                )
            else:
                fpc.write(f'         ret += "\\"{elt.name}\\":" + val_str;\n')
            fpc.write('          comma2 = ", ";\n')
            fpc.write("          break;\n")
            fpc.write("      }\n")
            ix += 1
        fpc.write(
            f'          default: fprintf(stderr, "variant default case: {self.name}\\n"); abort();\n'
        )
        fpc.write("      } // switch\n")
        # fcp.write('    ret += "}";\n')
        fpc.write('    comma = ", ";\n')
        fpc.write("  } // for values\n")
        fpc.write('  ret += "}";\n')
        fpc.write("  } // for map\n")
        fpc.write('  ret += "}";\n')
        fpc.write("  return ret;\n")
        fpc.write("}\n")
        fpc.write("\n")

    def generate_oneof_serializer(self, fp, fpc):
        for elt in self.members:
            elt.type.write_serializers(fp, fpc)

        fp.write(f"static std::string serialize(const {self.name}& obj);\n")
        fpc.write(f"std::string Endpoint::serialize(const {self.name}& obj) {{\n")
        fpc.write("  switch(obj.index()) {\n")

        for i in range(len(self.members)):
            m = self.members[i]
            fpc.write(f"  case {i}: \n")
            fpc.write(f"      return serialize(std::get<{i}>(obj));\n")

        fpc.write("  }\n")
        fpc.write('  INTERNAL_ERROR("internal error");\n')
        fpc.write("}\n")
        fpc.write("\n")

    def generate_enum_serializer(self, fp, fpc):
        fp.write(f"static std::string serialize(const {self.name}& obj);\n")
        fpc.write(f"std::string Endpoint::serialize(const {self.name}& obj) {{\n")
        fpc.write("  switch (obj) {\n")
        for elt in self.members:
            value = elt.value
            fpc.write(
                f'      case {self.name}::e_{elt.name}: return "\\"{value}\\"";\n'
            )
        fpc.write("  }\n")
        fpc.write('  return "internal error: enum not in case list";\n')
        fpc.write("}\n")
        fpc.write("\n")

    def write_serializers(self, fp, fpc):
        if self.generated_serializer_already:
            return
        self.generated_serializer_already = True
        match self.t:
            case ASTNodeEnum.OBJECT:
                self.generate_obj_serializer(fp, fpc)
            case ASTNodeEnum.ARRAY:
                self.members[0].type.write_serializers(fp, fpc)
            case ASTNodeEnum.PATTERN_PROPERTIES:
                self.generate_pattern_serializer(fp, fpc)
            case ASTNodeEnum.ANY_OF:
                self.generate_anyof_serializer(fp, fpc)
            case ASTNodeEnum.ONE_OF:
                self.generate_oneof_serializer(fp, fpc)
            case ASTNodeEnum.ALL_OF:
                self.generate_allof_serializer(fp, fpc)
            case ASTNodeEnum.ENUM:
                self.generate_enum_serializer(fp, fpc)
            case _:
                pass

    def is_format(self) -> bool:
        match self.t:
            case ASTNodeEnum.HOSTNAME:
                return True
            case ASTNodeEnum.IPV4:
                return True
            case ASTNodeEnum.IPV6:
                return True
            case _:
                return False
        return False

    def generate_obj_deserializer(self, fp, fpc):
        assert self.t != ASTNodeEnum.ANY_OF

        for elt in self.members:
            elt.type.write_deserializers(fp, fpc)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload);\n"
        )
        fpc.write(
            f" [[maybe_unused]] void Endpoint::deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )

        for elt in self.members:
            if elt.type.is_format():
                fpc.write(
                    f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                )
                fpc.write(f"	deserialize(obj._{elt.name}.value(), payload);\n")
            else:
                fpc.write(f'  if (payload.contains("{elt.orig_name}")) {{\n')
                if elt.default_value == None:
                    fpc.write(
                        f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                    )
                    fpc.write(
                        f'	deserialize(obj._{elt.name}.value(), payload["{elt.orig_name}"]);\n'
                    )
                else:
                    fpc.write(
                        f'	deserialize(obj._{elt.name}, payload["{elt.orig_name}"]);\n'
                    )
                fpc.write("   }\n")
        fpc.write("}\n")
        fpc.write("\n")

    def generate_pattern_deserializer(self, fp, fpc):
        for elt in self.members:
            elt.type.write_deserializers(fp, fpc)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& pattern_obj, [[maybe_unused]] const json& pattern_payload);\n"
        )

        fpc.write(
            f" [[maybe_unused]] void Endpoint::deserialize([[maybe_unused]] {self.name}& pattern_obj, [[maybe_unused]] const json& pattern_payload) {{\n"
        )

        fpc.write(
            "  for (auto pit = pattern_payload.begin(); pit != pattern_payload.end(); ++pit) {\n"
        )
        fpc.write(f"{self.name}::mapped_type values;\n")

        for elt in self.members:
            fpc.write(
                f'  if (const auto& found = pit->find("{elt.name}"); found != pit->end()) {{\n'
            )
            fpc.write(f"    {elt.type.name} val {{}};\n")
            fpc.write("    deserialize(val, *found);\n")
            fpc.write("    values.push_back(val);\n")
            fpc.write("  }\n")

        fpc.write(f"    pattern_obj[pit.key()] = values;\n")
        fpc.write("} // pit\n")
        fpc.write("}\n")
        fpc.write("\n")

    def generate_anyof_deserializer(self, fp, fpc):
        for elt in self.members:
            elt.type.write_deserializers(fp, fpc)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload);\n"
        )

        fpc.write(
            f" [[maybe_unused]] void Endpoint::deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )

        fpc.write("[[maybe_unused]] bool done = false;\n")

        for elt in self.members:
            fpc.write("try {\n")

            # anyof <format1,2,3> actually means
            # oneof..
            if elt.type.is_format():
                fpc.write("if (! done) {")
                fpc.write(
                    f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                )
                fpc.write(f"	deserialize(obj._{elt.name}.value(), payload);\n")
                fpc.write(f"	done = true;\n")
                fpc.write("	}\n")
            else:
                fpc.write(f'  if (payload.contains("{elt.orig_name}")) {{\n')
                if elt.default_value == None:
                    fpc.write(
                        f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                    )
                    fpc.write(
                        f'	deserialize(obj._{elt.name}.value(), payload["{elt.orig_name}"]);\n'
                    )
                else:
                    fpc.write(
                        f'	deserialize(obj._{elt.name}, payload["{elt.orig_name}"]);\n'
                    )
                fpc.write("   }\n")

            fpc.write("  } catch (const ParseError& e) {\n")
            fpc.write(f"   obj._{elt.name} = std::nullopt;\n")
            fpc.write("}\n")
        fpc.write("}\n")
        fpc.write("\n")

    def generate_allof_deserializer(self, fp, fpc):
        for elt in self.members:
            elt.type.write_deserializers(fp, fpc)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload);\n"
        )
        fpc.write(
            f" [[maybe_unused]] void Endpoint::deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )
        for elt in self.members:
            fpc.write(f'  if (payload.contains("{elt.name}")) {{\n')
            fpc.write(f'	    deserialize(obj._{elt.name}, payload["{elt.name}"]);\n')
            fpc.write("   }\n")
        fpc.write("}\n")
        fpc.write("\n")

    def generate_oneof_deserializer(self, fp, fpc):
        for elt in self.members:
            elt.type.write_deserializers(fp, fpc)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload);\n"
        )
        fpc.write(
            f" [[maybe_unused]] void Endpoint::deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )
        for elt in self.members:
            fpc.write("  try {\n")
            fpc.write(f"      {elt.type.name} val {{}};\n")
            fpc.write("      deserialize(val, payload);\n")
            fpc.write("      obj = val;\n")
            fpc.write("      return;\n")
            fpc.write("  } catch (const ParseError& e) {\n")
            fpc.write(f'       fprintf(stderr, "was not alt {elt.name}\\n");\n')
            fpc.write("  }\n")
        fpc.write(f'  THROW_ERROR("failed to parse {self.name}");\n')
        fpc.write("}\n")
        fpc.write("\n")

    def generate_enum_deserializer(self, fp, fpc):
        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload);\n"
        )
        fpc.write(
            f" [[maybe_unused]] void Endpoint::deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )
        for elt in self.members:
            value = elt.value
            fpc.write(
                f'	if (payload.dump() == "\\"{value}\\"") {{ obj = {self.name}::e_{elt.name}; return; }}\n'
            )
        fpc.write(
            '	THROW_ERROR("failed to find enum value for:" + payload.dump());\n'
        )
        fpc.write("}\n")
        fpc.write("\n")

    def write_deserializers(self, fp, fpc):
        if self.generated_deserializer_already:
            return
        self.generated_deserializer_already = True
        match self.t:
            case ASTNodeEnum.OBJECT:
                self.generate_obj_deserializer(fp, fpc)
            case ASTNodeEnum.ARRAY:
                # handled via template method
                self.members[0].type.write_deserializers(fp, fpc)
            case ASTNodeEnum.ANY_OF:
                self.generate_anyof_deserializer(fp, fpc)
            case ASTNodeEnum.PATTERN_PROPERTIES:
                self.generate_pattern_deserializer(fp, fpc)
            case ASTNodeEnum.ONE_OF:
                self.generate_oneof_deserializer(fp, fpc)
            case ASTNodeEnum.ALL_OF:
                self.generate_allof_deserializer(fp, fpc)
            case ASTNodeEnum.ENUM:
                self.generate_enum_deserializer(fp, fpc)
            case _:
                pass

    def __str__(self):
        return str(self.t)
