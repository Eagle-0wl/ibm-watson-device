map = Map("ibm")

section = map:section(NamedSection, "identity", "example", "Identification")

flag = section:option(Flag, "enable", "Enable", "Enable program")

orgId= section:option( Value, "orgId", "Organization id")
orgId.datatype = "string"
orgId.default = "zqo04f"
orgId.placeholder = "zqo04f"

typeId= section:option( Value, "typeId", "Device type")
typeId.datatype = "string"
typeId.default = "Router"
typeId.placeholder = "Router"

deviceId = section:option( Value, "deviceId", "Device id")
deviceId.datatype = "uinteger"
deviceId.default = "01"
deviceId.placeholder = "01"

token= section:option( Value, "token", "Token")
token.datatype = "string"
token.default = "hsfd98wer9sf98429s"
token.placeholder = "hsfd98wer9sf98429s"

return map
