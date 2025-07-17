package mcp

import (
	"github.com/ddkwork/golibrary/std/assert"
	"github.com/ddkwork/mcp/bindings/go/sdk"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ddkwork/golibrary/std/stream"
)

func TestDebug(t *testing.T) {
	d := sdk.Debugger{}
	assert.True(t, d.VmxSupportDetection())
	assert.Equal(t, "GenuineIntel", d.CpuReadVendorString())
	d.InstallVmmDriver()
	d.LoadVmmModule()
	println(d.ShowSignature())
	d.RunCommand("xxoo")
}

/* todo
 *  make all commands json file
 *  decode all error code text and send to client
 */
func Test_Bind_Go(t *testing.T) {
	os.RemoveAll("bindings")
	os.RemoveAll("tmp")
	stream.MarshalJsonToFile(apis, "mcp_api_meta.json")
	goType := map[string]string{
		"BOOLEAN":                             "bool",
		"BOOLEAN *":                           "bool", //todo see cpp server how to handle pointer
		"INT":                                 "int",
		"UINT32":                              "uint32",
		"UINT32 *":                            "uint32", //todo see cpp server how to handle pointer
		"UINT64":                              "uint64",
		"UINT64 *":                            "uint64", //todo see cpp server how to handle pointer
		"const CHAR *":                        "string",
		"const char *":                        "string",
		"const WCHAR *":                       "string", //todo utf16 ? 绑定其他枚举个结构体，调整很多返回值和形参位置移动
		"CHAR *":                              "string",
		"CHAR **":                             "[]string",
		"VOID":                                "void",
		"BYTE *":                              "[]byte", //todo test cpp server how to handle byte *
		"DWORD":                               "uint32", //?
		"PDEBUGGER_DT_COMMAND_OPTIONS":        "DEBUGGER_DT_COMMAND_OPTIONS",
		"DEBUGGER_READ_MEMORY_ADDRESS_MODE *": "DEBUGGER_READ_MEMORY_ADDRESS_MODE",
		"GUEST_REGS *":                        "GUEST_REGS",
		"GUEST_EXTRA_REGISTERS *":             "GUEST_EXTRA_REGISTERS",
		"INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS *": "INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS",
		"IO_APIC_ENTRY_PACKETS *":                      "IO_APIC_ENTRY_PACKETS",
		"DEBUGGER_READ_MEMORY_TYPE":                    "DEBUGGER_READ_MEMORY_TYPE",
		"PVOID":                                        "uint64",
		"REGS_ENUM":                                    "REGS_ENUM",
		"DEBUGGER_EDIT_MEMORY_TYPE":                    "DEBUGGER_EDIT_MEMORY_TYPE",
		"DEBUGGER_READ_READING_TYPE":                   "DEBUGGER_READ_READING_TYPE",
		"DEBUGGER_SHOW_MEMORY_STYLE":                   "DEBUGGER_SHOW_MEMORY_STYLE",
		"PLAPIC_PAGE":                                  "PLAPIC_PAGE",
		//    mcp_test.go:87: unknown param type: register_id
	}
	g := stream.NewGeneratedFile()
	g.P("type Debugger struct {}")
	for _, api := range apis {
		params := ""
		for i, param := range api.Params {
			params += param.Name + " " + goType[param.Type]
			if i < len(api.Params)-1 {
				params += ", "
			}
		}
		returnType := goType[api.ReturnType]
		returnSyntax := "return"
		if api.ReturnType == "VOID" {
			returnType = ""
			returnSyntax = ""
		}
		g.P("func (Debugger) ", api.Name, "("+params, ") ", returnType, " {")

		var callParams string
		for i, param := range api.Params {
			callParams += "\t\t" + strconv.Quote(param.Name) + ":"
			switch param.Type {
			case "BOOLEAN", "BOOLEAN *":
				callParams += "strconv.FormatBool(" + param.Name + ")"
			case "INT":
				callParams += "strconv.Itoa(" + param.Name + ")"
			case "UINT32", "DWORD", "UINT32 *": //todo see cpp server how to handle pointer
				callParams += "strconv.FormatUint(uint64(" + param.Name + "), 10)"
			case "UINT64":
				callParams += "strconv.FormatUint(" + param.Name + ", 10)"
			//case "const CHAR *":
			//	callParams += param.Name
			case "CHAR **":
				callParams += "strings.Join(tokens_list, " +
					"\" \"" + //todo test cpp server how to handle char **")
					")"
			case "const WCHAR *":
				callParams += param.Name
			case "CHAR *", "const CHAR *", "const char *":
				callParams += param.Name
			case "BYTE *":
				callParams += "hex.EncodeToString(" + param.Name + ")"
			case "VOID":
				callParams += "None"
			case "PDEBUGGER_DT_COMMAND_OPTIONS",
				"PDEBUGGER_DT_COMMAND_OPTIONS *",
				"GUEST_REGS *",
				"IO_APIC_ENTRY_PACKETS *",
				"GUEST_EXTRA_REGISTERS *",
				"INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS *",
				"PLAPIC_PAGE *",
				"IO_APIC_ENTRY_PACKETS",
				"INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS",
				"GUEST_REGS",
				"PLAPIC_PAGE",
				"GUEST_EXTRA_REGISTERS":
				callParams += "string(stream.MarshalJSON(" + param.Name + "))"
			case "DEBUGGER_EDIT_MEMORY_TYPE",
				"DEBUGGER_READ_READING_TYPE",
				"DEBUGGER_SHOW_MEMORY_STYLE",
				"DEBUGGER_READ_MEMORY_TYPE",
				"DEBUGGER_READ_MEMORY_ADDRESS_MODE",
				"DEBUGGER_READ_MEMORY_ADDRESS_MODE *",
				"REGS_ENUM",
				"REGS_ENUM *",
				"DEBUGGER_EDIT_MEMORY_TYPE *",
				"DEBUGGER_READ_READING_TYPE *",
				"DEBUGGER_SHOW_MEMORY_STYLE *",
				"DEBUGGER_READ_MEMORY_TYPE *",
				"UINT64 *",
				"PVOID":
				callParams += "strconv.FormatUint(uint64(" + param.Name + "),10)"

			default:
				callParams += strconv.Quote("todo panic --> unknown param type:" + param.Type)
				t.Error("unknown param type:", param.Type, " api:", api.Name)
			}
			if i < len(api.Params) {
				callParams += ","
			}
			if len(api.Params) > 1 {
				if i == 0 {
					callParams = "\n" + callParams
				}
				callParams += "\n"
			}
		}
		paramsMap := "map[string]string{" + callParams + "}"
		if api.Params == nil {
			paramsMap = "nil"
		}
		g.P("\t", returnSyntax, " request[", goType[api.ReturnType], "](", strconv.Quote(api.Name), ",", paramsMap, ")")
		g.P("}")
	}
	//g.AddImport("strings")
	g.AddImport("encoding/hex")
	//g.AddImport("encoding/json")
	g.AddImport("github.com/ddkwork/golibrary/std/stream")
	//g.AddImport("fmt")
	g.AddImport("strconv")
	g.InsertPackageWithImports("sdk")
	b := stream.NewBuffer("request.go").ReplaceAll("package mcp", "package sdk")
	stream.WriteGoFile("bindings/go/sdk/request.go", b.String())
	//stream.WriteGoFile("tmp/bindings/go/sdk/request.go", b.String())
	stream.WriteGoFile(filepath.Join("bindings/go/sdk/sdk.go"), g.String())

	//generate other language bindings
	Test_Gen_Cpp_Server_Code(t)
	Test_Bind_V(t)
	Test_Bind_Python(t)
	Test_Bind_Csharp(t)
	Test_Bind_Javascript(t)
	Test_Bind_Rust(t)
	Test_Bind_Java(t)
	Test_Bind_Haskell(t)
	Test_Bind_Masm(t)
	Test_Bind_Nodejs(t)
	Test_Bind_Ocaml(t)
	Test_Bind_PowerShell(t)
	Test_Bind_Ruby(t)
	Test_Bind_Vb6(t)
}
func Test_Gen_Cpp_Server_Code(t *testing.T) {
	//else if (path == "/CpuReadVendorString") {
	//                    char vendorString[13];
	//                    CpuReadVendorString(vendorString);
	//                    sendHttpResponse(clientSocket, 200, "text/plain", vendorString);
	//                }
	g := stream.NewGeneratedFile()
	for _, api := range apis {
		g.P("else if (path == " +
			strconv.Quote(api.Name) +
			") {")
		//g.P("//todo handle params`")
		g.P("}")
	}
	stream.WriteTruncate("echo.h", g.String())

}
func Test_Bind_V(t *testing.T) {}
func Test_Bind_Python(t *testing.T) {
	start := `
import sys
import requests
import json

from mcp.server.fastmcp import FastMCP

DEFAULT_HyperDBG_SERVER = "http://127.0.0.1:8888/"
hyperdbg_server_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HyperDBG_SERVER

mcp = FastMCP("hyperdbg-mcp")

def safe_get(endpoint: str, params: dict = None):
    """
    Perform a GET request with optional query parameters.
    Returns parsed JSON if possible, otherwise text content
    """
    if params is None:
        params = {}

    url = f"{hyperdbg_server_url}{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=15)
        response.encoding = 'utf-8'
        if response.ok:
            # Try to parse as JSON first
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post(endpoint: str, data: dict | str):
    """
    Perform a POST request with data.
    Returns parsed JSON if possible, otherwise text content
    """
    try:
        url = f"{hyperdbg_server_url}{endpoint}"
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        
        response.encoding = 'utf-8'
        
        if response.ok:
            # Try to parse as JSON first
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"
`
	g := stream.NewGeneratedFile()
	g.P(start)
	for _, api := range apis {
		g.P("@mcp.tool()")
		//ai model 提示词
		g.P("def ", api.Name, "()")
		//g.P("    return safe_post('mcp/api/"+api.Name+"', {'"+api.Params[0].Name+"': "+api.Params[0].Name+"})")
		g.P("")
	}
	g.P("if __name__ == \"__main__\":\n    mcp.run()")
	stream.WriteTruncate("bindings/python/sdk.py", g.String())
}

func Test_Bind_Csharp(t *testing.T)     {}
func Test_Bind_Javascript(t *testing.T) {}
func Test_Bind_Rust(t *testing.T)       {}
func Test_Bind_Java(t *testing.T)       {}
func Test_Bind_Haskell(t *testing.T)    {}
func Test_Bind_Masm(t *testing.T)       {}
func Test_Bind_Nodejs(t *testing.T)     {}
func Test_Bind_Ocaml(t *testing.T)      {}
func Test_Bind_PowerShell(t *testing.T) {}
func Test_Bind_Ruby(t *testing.T)       {}
func Test_Bind_Vb6(t *testing.T)        {}

type ApiMeta struct {
	Name       string
	Params     []NameType
	ReturnType string
}

type NameType struct {
	Name string
	Type string
}

var apis = []ApiMeta{
	{
		Name:       "VmxSupportDetection",
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "CpuReadVendorString",
		Params:     nil,
		ReturnType: "CHAR *",
	},
	{
		Name:       "LoadVmmModule",
		Params:     nil,
		ReturnType: "CHAR *",
	},
	{
		Name:       "UnloadVmm",
		Params:     nil,
		ReturnType: "CHAR *",
	},
	{
		Name:       "InstallVmmDriver",
		Params:     nil,
		ReturnType: "CHAR *",
	},

	{
		Name:       "UninstallVmmDriver",
		Params:     nil,
		ReturnType: "CHAR *",
	},
	{
		Name:       "StopVmmDriver",
		Params:     nil,
		ReturnType: "CHAR *",
	},
	{
		Name: "RunCommand",
		Params: []NameType{
			{
				Name: "command",
				Type: "CHAR *",
			},
		},
		ReturnType: "CHAR *",
	},
	{
		Name: "TestCommandParserShowTokens",
		Params: []NameType{
			{
				Name: "command",
				Type: "CHAR *",
			},
		},
		ReturnType: "CHAR *",
	},

	{
		Name:       "ShowSignature",
		Params:     nil,
		ReturnType: "CHAR *",
	},

	{
		Name:       "ContinuePreviousCommand",
		Params:     nil,
		ReturnType: "BOOLEAN",
	},

	{
		Name: "CheckMultilineCommand",
		Params: []NameType{
			{
				Name: "current_command",
				Type: "CHAR *",
			},
			{
				Name: "reset",
				Type: "BOOLEAN",
			},
		},
		ReturnType: "BOOLEAN",
	},
	///////////////////////////////////////////////////
	{
		Name:       "ConnectLocalDebugger",
		Params:     nil,
		ReturnType: "VOID",
	},
	{
		Name: "ConnectRemoteDebugger",
		Params: []NameType{
			{
				Name: "ip",
				Type: "const CHAR *",
			},
			{
				Name: "port",
				Type: "const CHAR *",
			},
		},
		ReturnType: "CHAR *",
	},
	{
		Name:       "Continue", //c api CommandGRequest
		Params:     nil,
		ReturnType: "VOID",
	},
	{
		Name:       "Pause", //c api CommandPauseRequest
		Params:     nil,
		ReturnType: "VOID",
	},
	{
		Name: "SetBreakPoint", //c api CommandBpRequest
		Params: []NameType{
			{
				Name: "address",
				Type: "UINT64",
			},
			{
				Name: "pid",
				Type: "UINT32",
			},
			{
				Name: "tid",
				Type: "UINT32",
			}, {
				Name: "core_numer",
				Type: "UINT32",
			},
		},
		ReturnType: "VOID",
	},
	{
		Name: "SetCustomDriverPath", //set_custom_driver_path , no c api
		Params: []NameType{
			{
				Name: "driver_file_path",
				Type: "CHAR *",
			},
			{
				Name: "driver_name",
				Type: "CHAR *",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "UseDefaultDriverPath", //use_default_driver_path,NO c api
		Params:     nil,
		ReturnType: "VOID",
	},
	{
		Name: "ReadMemory", //todo 处理参数是指针类型的格式化操作，参数太多了
		Params: []NameType{
			{
				Name: "target_address",
				Type: "UINT64",
			},
			{
				Name: "memory_type",
				Type: "DEBUGGER_READ_MEMORY_TYPE", //todo gen enum type
			},
			{
				Name: "reading_Type",
				Type: "DEBUGGER_READ_READING_TYPE",
			},
			{
				Name: "pid",
				Type: "UINT32",
			},
			{
				Name: "size",
				Type: "UINT32",
			},
			{
				Name: "get_address_mode",
				Type: "BOOLEAN",
			},
			{
				Name: "address_mode",
				Type: "DEBUGGER_READ_MEMORY_ADDRESS_MODE *",
			},
			{
				Name: "target_buffer_to_store",
				Type: "BYTE *",
			},
			{
				Name: "return_length",
				Type: "UINT32 *",
			},
		},
		ReturnType: "BOOLEAN", //todo 改变返回值类型 bytes buffer return need to be changed
	},
	{
		Name: "ShowMemoryOrDisassemble",
		Params: []NameType{
			{
				Name: "style",
				Type: "DEBUGGER_SHOW_MEMORY_STYLE",
			},
			{
				Name: "address",
				Type: "UINT64",
			},
			{
				Name: "memory_type",
				Type: "DEBUGGER_READ_MEMORY_TYPE",
			},
			{
				Name: "reading_type",
				Type: "DEBUGGER_READ_READING_TYPE",
			},
			{
				Name: "pid",
				Type: "UINT32",
			},
			{
				Name: "size",
				Type: "UINT32",
			},
			{
				Name: "dt_details",
				Type: "PDEBUGGER_DT_COMMAND_OPTIONS",
			},
		},
		ReturnType: "VOID", //TODO
	},
	{
		Name: "ReadAllRegisters",
		Params: []NameType{
			{
				Name: "guest_registers",
				Type: "GUEST_REGS *",
			},
			{
				Name: "extra_registers",
				Type: "GUEST_EXTRA_REGISTERS *",
			},
		},
		ReturnType: "BOOLEAN", //todo 返回结构体
	},
	//{
	//	Name: "xxxxxxxxxxxxxxxxxxx",
	//	Params: []NameType{
	//		{
	//			Name: "xxxxxxxxxxxxxx",
	//			Type: "xxxxxxxxxxxxxxx",
	//		},
	//		{
	//			Name: "xxxxxxxxxx",
	//			Type: "xxxxxxxxxx",
	//		},
	//	},
	//	ReturnType: "xxxxxxxxxxxxxxxxx",
	//},
	{
		Name: "ReadTargetRegister",
		Params: []NameType{
			{
				Name: "register_id",
				Type: "REGS_ENUM",
			},
			{
				Name: "target_register",
				Type: "UINT64 *",
			},
		},
		ReturnType: "BOOLEAN", //todo 返回结构体
	},
	{
		Name: "WriteTargetRegister",
		Params: []NameType{
			{
				Name: "register_id",
				Type: "REGS_ENUM",
			},
			{
				Name: "value",
				Type: "UINT64",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "RegisterShowAll", //?
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
	{
		Name: "RegisterShowTargetRegister",
		Params: []NameType{
			{
				Name: "register_id",
				Type: "REGS_ENUM",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "WriteMemory",
		Params: []NameType{
			{
				Name: "destination_address",
				Type: "PVOID",
			},
			{
				Name: "memory_type",
				Type: "DEBUGGER_EDIT_MEMORY_TYPE",
			},
			{
				Name: "process_id",
				Type: "UINT32",
			},
			{
				Name: "source_address",
				Type: "PVOID",
			},
			{
				Name: "number_of_bytes",
				Type: "UINT32",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "DebuggerGetKernelBase",
		Params:     nil,
		ReturnType: "UINT64",
	},
	{
		Name: "DebugRemoteDeviceUsingComPort",
		Params: []NameType{
			{
				Name: "port_name",
				Type: "const CHAR *",
			},
			{
				Name: "baudrate",
				Type: "DWORD",
			},
			{
				Name: "pause_after_connection",
				Type: "BOOLEAN",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "DebugRemoteDeviceUsingNamedPipe",
		Params: []NameType{
			{
				Name: "named_pipe",
				Type: "const CHAR *",
			},
			{
				Name: "pause_after_connection",
				Type: "BOOLEAN",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "DebugCloseRemoteDebugger",
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
	{
		Name: "DebugCurrentDeviceUsingComPort",
		Params: []NameType{
			{
				Name: "port_name",
				Type: "const CHAR *",
			},
			{
				Name: "baudrate",
				Type: "DWORD",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "StartProcess",
		Params: []NameType{
			{
				Name: "path",
				Type: "const WCHAR *", //todo
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "StartProcessWithArgs",
		Params: []NameType{
			{
				Name: "path",
				Type: "const WCHAR *",
			},
			{
				Name: "arguments",
				Type: "const WCHAR *",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "AssembleGetLength",
		Params: []NameType{
			{
				Name: "assembly_code",
				Type: "const CHAR *",
			},
			{
				Name: "start_address",
				Type: "UINT64",
			},
			{
				Name: "length",
				Type: "UINT32 *", //todo move to return
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "Assemble",
		Params: []NameType{
			{
				Name: "assembly_code",
				Type: "const CHAR *",
			},
			{
				Name: "start_address",
				Type: "UINT64",
			},
			{
				Name: "buffer_to_store_assembled_data",
				Type: "PVOID",
			},
			{
				Name: "buffer_size", //?
				Type: "UINT32",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "SetupPathForFileName",
		Params: []NameType{
			{
				Name: "filename",
				Type: "const CHAR *",
			},
			{
				Name: "file_location",
				Type: "CHAR *",
			},
			{
				Name: "buffer_len",
				Type: "UINT32",
			},
			{
				Name: "check_file_existence",
				Type: "BOOLEAN",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "SteppingInstrumentationStepIn", //todo rename
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "SteppingRegularStepIn",
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "SteppingStepOver",
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "SteppingInstrumentationStepInForTracking",
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
	{
		Name: "SteppingStepOverForGu",
		Params: []NameType{
			{
				Name: "last_instruction",
				Type: "BOOLEAN",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "GetLocalApic",
		Params: []NameType{
			{
				Name: "local_apic",
				Type: "PLAPIC_PAGE",
			},
			{
				Name: "is_using_x2apic",
				Type: "BOOLEAN *", //?
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "GetIoApic",
		Params: []NameType{
			{
				Name: "io_apic",
				Type: "IO_APIC_ENTRY_PACKETS *", //?
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "GetIdtEntry",
		Params: []NameType{
			{
				Name: "idt_packet",
				Type: "INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS *", //todo move into return
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "HwdbgScriptRunScript",
		Params: []NameType{
			{
				Name: "script",
				Type: "const CHAR *",
			},
			{
				Name: "instance_filepath_to_read",
				Type: "const CHAR *",
			},
			{
				Name: "hardware_script_file_path_to_save",
				Type: "const CHAR *",
			},
			{
				Name: "initial_bram_buffer_size",
				Type: "UINT32",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name: "ScriptEngineWrapperTestParserForHwdbg",
		Params: []NameType{
			{
				Name: "Expr",
				Type: "const char *",
			},
		},
		ReturnType: "VOID",
	},
	{
		Name: "EnableTransparentMode",
		Params: []NameType{
			{
				Name: "ProcessId",
				Type: "UINT32",
			},
			{
				Name: "ProcessName",
				Type: "CHAR *",
			},
			{
				Name: "IsProcessId",
				Type: "BOOLEAN",
			},
		},
		ReturnType: "BOOLEAN",
	},
	{
		Name:       "DisableTransparentMode",
		Params:     nil,
		ReturnType: "BOOLEAN",
	},
}
