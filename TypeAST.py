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
    ix = s.find('_')
    if ix > 0 and ((ix + 1) < len(s)):
        s = s[0] + s[ix + 1]

    s = s.replace(':', '')

    if s=="stdstring":
        s = "string"
    if s=="wwwRegEx":
        s = "regEx"

    if len(s) > MAX_TYPE_NAME_LENGTH:
        s = s[0:MAX_TYPE_NAME_LENGTH]

    if s.endswith("_"):
        s = s[0:len(s)-1]

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
    NULL = "NULL",
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
unique_enums: List['ASTType'] = []


def reset_global_state():
    global glob_counter
    glob_counter = 0
    enum_name_map.clear()
    unique_enums.clear()


def register_unique_enum(t: 'ASTType') -> 'ASTType':
    assert t.t == ASTNodeEnum.ENUM
    for uniq in unique_enums:
        if uniq.equals(t):
            return uniq
    unique_enums.append(t)
    t.give_enum_a_unique_name()
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
        self.generated_serializer_already =  False
        self.generated_deserializer_already =  False
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
            k = k[0:len(k)-1]

        if len(k)>MAX_TYPE_NAME_LENGTH:
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
        #self.single_inline()
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
            #if p.type.t == ASTNodeEnum.PATTERN_PROPERTIES:
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

        if enum_name.endswith('_'):
            enum_name = enum_name[0:len(enum_name)-1]

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
            m1.name = m1.name.replace(':', '')

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

    def remove_duplicate_enums(self) -> 'ASTType':
        for m in self.members:
            m.type = m.type.remove_duplicate_enums()

        if self.t == ASTNodeEnum.ENUM:
            return register_unique_enum(self)
        return self

    def normalize(self):
        self.flatten()
        if self.t == ASTNodeEnum.ALL_OF:
            print(self)

        self.remove_duplicate_members()
        self.remove_duplicate_enums()
        self.fix_members_with_same_name_different_types()

    def generate_enum(self, fp):
        fp.write(f"enum class {self.name} {{\n")
        comma = ""
        for e in self.members:
            fp.write(f"\t{comma} e_{e.name}\n")
            comma = ","
        fp.write("};\n\n")

    def generate_obj(self, fp):
        for elt in self.members:
            elt.type.write_types(fp)

        fp.write(f"struct {self.name} {{\n")
        for elt in self.members:
            init = ""
            if elt.default_value != None:
                init = value_to_c(elt.default_value)
                fp.write(f"\t{elt.type.name} _{elt.name} = {init}; // {elt.orig_name}\n")
            else:
                fp.write(f"\tstd::optional<{elt.type.name}> _{elt.name};  // {elt.orig_name}\n")

        fp.write(f"}}; // {self.name}\n\n")

    def generate_array(self, fp):
        self.members[0].type.write_types(fp)
        elts = self.members[0].type.name
        fp.write(f"using {self.name} = std::vector<{elts}>;\n")

    def generate_anyof(self, fp):
        for elt in self.members:
            elt.type.write_types(fp)

        fp.write(f"struct {self.name} {{\n")
        for elt in self.members:
            fp.write(f"\tstd::optional<{elt.type.name}> _{elt.name}; // {elt.orig_name}\n")
        fp.write(f"}}; // {self.name}\n\n")

    def generate_pattern(self, fp):
        elt_names = ""
        comma = ""
        for elt in self.members:
            elt.type.write_types(fp)
            elt_names += f"{comma}{elt.type.name}"
            comma = ", "

        fp.write(f"using {self.name} = std::map<std::string, std::vector<std::variant<{elt_names}>>>;\n")

    def generate_allof(self, fp):
        for elt in self.members:
            elt.type.write_types(fp)

        fp.write(f"struct {self.name} {{\n")
        for elt in self.members:
            fp.write(f"\t{elt.type.name} _{elt.name};  // {elt.orig_name}\n")
        fp.write(f"}}; // {self.name}\n\n")

    def generate_oneof(self, fp):
        for elt in self.members:
            elt.type.write_types(fp)

        comma = ""
        fp.write(f"using {self.name} = std::variant<")
        for elts in self.members:
            fp.write(f"{comma}{elts.type.name}")
            comma = ", "
        fp.write(">;\n")

    def write_types(self, fp):
        if self.generated_type_already:
            return
        self.generated_type_already = True
        match self.t:
            case ASTNodeEnum.OBJECT:
                self.generate_obj(fp)
            case ASTNodeEnum.ARRAY:
                self.generate_array(fp)
            case ASTNodeEnum.ANY_OF:
                self.generate_anyof(fp)
            case ASTNodeEnum.PATTERN_PROPERTIES:
                self.generate_pattern(fp)
            case ASTNodeEnum.ONE_OF:
                self.generate_oneof(fp)
            case ASTNodeEnum.ALL_OF:
                self.generate_allof(fp)
            case ASTNodeEnum.ENUM:
                self.generate_enum(fp)
            case ASTNodeEnum.ENUM_ENTRY:
                raise RuntimeError("unhandled")

    def is_inline(self):
        return self.members[0].name.startswith("_field_")

    def _generic_serialize(self, fp):
        if len(self.members) == 0:
            fp.write(f"static std::string serialize(const {self.name}& ) {{\n")
            fp.write("  // type has no members\n")
            fp.write("  return \"{}\";\n")
            fp.write("}\n")
            fp.write("\n")
            return;

        for elt in self.members:
            elt.type.write_serializers(fp)

        fp.write(f"static std::string serialize(const {self.name}& obj) {{\n")

        fp.write('  std::string ret;\n')
        fp.write('  std::string comma;\n')

        if self.is_inline():
            for elt in self.members:
                fp.write(f'  if (const auto k = serialize(obj._{elt.name}); k != "") {{\n')
                fp.write('     ret += comma;\n')
                fp.write('     comma = ", ";\n')
                fp.write(f'     ret += k;\n')
                fp.write('  }\n')
        else:
            fp.write('  ret += "{";\n')
            for elt in self.members:
                fp.write(f'  if (const auto k = serialize(obj._{elt.name}); k != "") {{\n')
                fp.write('     ret += comma;\n')
                fp.write('     comma = ", ";\n')
                fp.write(f'     ret += "\\\"{elt.orig_name}\\\":" + k;\n')
                fp.write('  }\n')
            fp.write('  ret += "}";\n')
        fp.write('  return ret;\n')
        fp.write("}\n")
        fp.write("\n")

    def generate_obj_serializer(self, fp):
        self._generic_serialize(fp)

    def generate_allof_serializer(self, fp):
        self._generic_serialize(fp)

    def generate_anyof_serializer(self, fp):
        self._generic_serialize(fp)

    def generate_pattern_serializer(self, fp):
        for elt in self.members:
            elt.type.write_serializers(fp)

        fp.write(f"static std::string serialize(const {self.name}& map) {{\n")
        fp.write('  std::string ret = "{";\n')
        fp.write('  const char* comma = "";\n')
        fp.write('  for (const auto& [key, values] : map) {\n')
        fp.write('    ret += comma;\n')
        fp.write('    ret += "\\""+key+"\\":{\";\n')

        fp.write('    const char* comma2 = "";\n')
        fp.write('    for (const auto& val : values) {\n')
        fp.write('      ret += comma2;\n')

        ix = 0;
        fp.write('      switch (val.index()) {\n')
        for elt in self.members:
            fp.write(f'      case {ix}: {{\n')
            fp.write(f'         const auto val_str = serialize(std::get<{ix}>(val));\n')
            fp.write(f'         ret += "\\"{elt.name}\\":" + val_str;\n')
            fp.write('          comma2 = ", ";\n')
            fp.write('          break;\n')
            fp.write('      }\n')
            ix += 1
        fp.write(f'          default: fprintf(stderr, "variant default case: {self.name}\\n"); abort();\n')
        fp.write('      } // switch\n')
        #fp.write('    ret += "}";\n')
        fp.write('    comma = ", ";\n')
        fp.write("  } // for values\n")
        fp.write('  ret += "}";\n')
        fp.write("  } // for map\n")
        fp.write('  ret += "}";\n')
        fp.write('  return ret;\n')
        fp.write("}\n")
        fp.write("\n")

    def generate_oneof_serializer(self, fp):
        for elt in self.members:
            elt.type.write_serializers(fp)

        fp.write(f"static std::string serialize(const {self.name}& obj) {{\n")
        fp.write('  switch(obj.index()) {\n')

        for i in range(len(self.members)):
            m = self.members[i]
            fp.write(f'  case {i}: \n')
            fp.write(f'      return serialize(std::get<{i}>(obj));\n')

        fp.write("  }\n")
        fp.write('  INTERNAL_ERROR("internal error");\n')
        fp.write("}\n")
        fp.write("\n")



    def generate_enum_serializer(self, fp):
        fp.write(f"static std::string serialize(const {self.name}& obj) {{\n")
        fp.write("  switch (obj) {\n")
        for elt in self.members:
            value = elt.value
            fp.write(f'      case {self.name}::e_{elt.name}: return "\\"{value}\\"";\n')
        fp.write("  }\n")
        fp.write('  return "internal error: enum not in case list";\n')
        fp.write("}\n")
        fp.write("\n")

    def write_serializers(self, fp):
        if self.generated_serializer_already:
            return
        self.generated_serializer_already = True
        match self.t:
            case ASTNodeEnum.OBJECT:
                self.generate_obj_serializer(fp)
            case ASTNodeEnum.ARRAY:
                self.members[0].type.write_serializers(fp)
            case ASTNodeEnum.PATTERN_PROPERTIES:
                self.generate_pattern_serializer(fp)
            case ASTNodeEnum.ANY_OF:
                self.generate_anyof_serializer(fp)
            case ASTNodeEnum.ONE_OF:
                self.generate_oneof_serializer(fp)
            case ASTNodeEnum.ALL_OF:
                self.generate_allof_serializer(fp)
            case ASTNodeEnum.ENUM:
                self.generate_enum_serializer(fp)
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


    def generate_obj_deserializer(self, fp):
        assert self.t != ASTNodeEnum.ANY_OF

        for elt in self.members:
            elt.type.write_deserializers(fp)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )

        for elt in self.members:
            if elt.type.is_format():
                fp.write(
                    f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                )
                fp.write(f'	deserialize(obj._{elt.name}.value(), payload);\n')
            else:
                fp.write(f'  if (payload.contains("{elt.orig_name}")) {{\n')
                if elt.default_value == None:
                    fp.write(
                        f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                    )
                    fp.write(f'	deserialize(obj._{elt.name}.value(), payload["{elt.orig_name}"]);\n')
                else:
                    fp.write(f'	deserialize(obj._{elt.name}, payload["{elt.orig_name}"]);\n')
                fp.write('   }\n')
        fp.write("}\n")
        fp.write("\n")

    def generate_pattern_deserializer(self, fp):
        for elt in self.members:
            elt.type.write_deserializers(fp)
        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& pattern_obj, [[maybe_unused]] const json& pattern_payload) {{\n"
        )

        fp.write('  for (auto pit = pattern_payload.begin(); pit != pattern_payload.end(); ++pit) {\n')
        fp.write(f'{self.name}::mapped_type values;\n')

        for elt in self.members:
            fp.write(f'  if (const auto& found = pit->find("{elt.name}"); found != pit->end()) {{\n')
            fp.write(f'    {elt.type.name} val {{}};\n')
            fp.write('    deserialize(val, *found);\n')
            fp.write('    values.push_back(val);\n')
            fp.write("  }\n")

        fp.write(f'    pattern_obj[pit.key()] = values;\n')
        fp.write("} // pit\n")
        fp.write("}\n")
        fp.write("\n")

    def generate_anyof_deserializer(self, fp):
        for elt in self.members:
            elt.type.write_deserializers(fp)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )

        fp.write("[[maybe_unused]] bool done = false;\n")

        for elt in self.members:
            fp.write("try {\n")

            # anyof <format1,2,3> actually means
            # oneof..
            if elt.type.is_format():
                fp.write("if (! done) {")
                fp.write(
                    f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                )
                fp.write(f'	deserialize(obj._{elt.name}.value(), payload);\n')
                fp.write(f'	done = true;\n')
                fp.write('	}\n')
            else:
                fp.write(f'  if (payload.contains("{elt.orig_name}")) {{\n')
                if elt.default_value == None:
                    fp.write(
                        f"	obj._{elt.name} = decltype(obj._{elt.name})::value_type {{}};\n"
                    )
                    fp.write(f'	deserialize(obj._{elt.name}.value(), payload["{elt.orig_name}"]);\n')
                else:
                    fp.write(f'	deserialize(obj._{elt.name}, payload["{elt.orig_name}"]);\n')
                fp.write('   }\n')

            fp.write("  } catch (const ParseError& e) {\n")
            fp.write(f"   obj._{elt.name} = std::nullopt;\n")
            fp.write("}\n")
        fp.write("}\n")
        fp.write("\n")

    def generate_allof_deserializer(self, fp):
        for elt in self.members:
            elt.type.write_deserializers(fp)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )
        for elt in self.members:
            fp.write(f'  if (payload.contains("{elt.name}")) {{\n')
            fp.write(f'	    deserialize(obj._{elt.name}, payload["{elt.name}"]);\n')
            fp.write('   }\n')

        fp.write("}\n")
        fp.write("\n")

    def generate_oneof_deserializer(self, fp):
        for elt in self.members:
            elt.type.write_deserializers(fp)

        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )
        for elt in self.members:
            fp.write("  try {\n")
            fp.write(f"      {elt.type.name} val {{}};\n")
            fp.write("      deserialize(val, payload);\n")
            fp.write("      obj = val;\n")
            fp.write("      return;\n")
            fp.write("  } catch (const ParseError& e) {\n")
            fp.write(f'       fprintf(stderr, "was not alt {elt.name}\\n");\n')
            fp.write("  }\n")
        fp.write(f'  THROW_ERROR("failed to parse {self.name}");\n')
        fp.write("}\n")
        fp.write("\n")


    def generate_enum_deserializer(self, fp):
        fp.write(
            f" [[maybe_unused]] static void deserialize([[maybe_unused]] {self.name}& obj, [[maybe_unused]] const json& payload) {{\n"
        )
        for elt in self.members:
            value = elt.value
            fp.write(
                f'	if (payload.dump() == "\\"{value}\\"") {{ obj = {self.name}::e_{elt.name}; return; }}\n'
            )
        fp.write(
            '	THROW_ERROR("failed to find enum value for:" + payload.dump());\n'
        )
        fp.write("}\n")
        fp.write("\n")

    def write_deserializers(self, fp):
        if self.generated_deserializer_already:
            return
        self.generated_deserializer_already = True
        match self.t:
            case ASTNodeEnum.OBJECT:
                self.generate_obj_deserializer(fp)
            case ASTNodeEnum.ARRAY:
                # handled via template method
                self.members[0].type.write_deserializers(fp)
            case ASTNodeEnum.ANY_OF:
                self.generate_anyof_deserializer(fp)
            case ASTNodeEnum.PATTERN_PROPERTIES:
                self.generate_pattern_deserializer(fp)
            case ASTNodeEnum.ONE_OF:
                self.generate_oneof_deserializer(fp)
            case ASTNodeEnum.ALL_OF:
                self.generate_allof_deserializer(fp)
            case ASTNodeEnum.ENUM:
                self.generate_enum_deserializer(fp)
            case _:
                pass

    def __str__(self):
        return str(self.t)
