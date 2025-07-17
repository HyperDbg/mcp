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
@mcp.tool()
def VmxSupportDetection()

@mcp.tool()
def CpuReadVendorString()

@mcp.tool()
def LoadVmmModule()

@mcp.tool()
def UnloadVmm()

@mcp.tool()
def InstallVmmDriver()

@mcp.tool()
def UninstallVmmDriver()

@mcp.tool()
def StopVmmDriver()

@mcp.tool()
def RunCommand()

@mcp.tool()
def TestCommandParserShowTokens()

@mcp.tool()
def ShowSignature()

@mcp.tool()
def ContinuePreviousCommand()

@mcp.tool()
def CheckMultilineCommand()

@mcp.tool()
def ConnectLocalDebugger()

@mcp.tool()
def ConnectRemoteDebugger()

@mcp.tool()
def Continue()

@mcp.tool()
def Pause()

@mcp.tool()
def SetBreakPoint()

@mcp.tool()
def SetCustomDriverPath()

@mcp.tool()
def UseDefaultDriverPath()

@mcp.tool()
def ReadMemory()

@mcp.tool()
def ShowMemoryOrDisassemble()

@mcp.tool()
def ReadAllRegisters()

@mcp.tool()
def ReadTargetRegister()

@mcp.tool()
def WriteTargetRegister()

@mcp.tool()
def RegisterShowAll()

@mcp.tool()
def RegisterShowTargetRegister()

@mcp.tool()
def WriteMemory()

@mcp.tool()
def DebuggerGetKernelBase()

@mcp.tool()
def DebugRemoteDeviceUsingComPort()

@mcp.tool()
def DebugRemoteDeviceUsingNamedPipe()

@mcp.tool()
def DebugCloseRemoteDebugger()

@mcp.tool()
def DebugCurrentDeviceUsingComPort()

@mcp.tool()
def StartProcess()

@mcp.tool()
def StartProcessWithArgs()

@mcp.tool()
def AssembleGetLength()

@mcp.tool()
def Assemble()

@mcp.tool()
def SetupPathForFileName()

@mcp.tool()
def SteppingInstrumentationStepIn()

@mcp.tool()
def SteppingRegularStepIn()

@mcp.tool()
def SteppingStepOver()

@mcp.tool()
def SteppingInstrumentationStepInForTracking()

@mcp.tool()
def SteppingStepOverForGu()

@mcp.tool()
def GetLocalApic()

@mcp.tool()
def GetIoApic()

@mcp.tool()
def GetIdtEntry()

@mcp.tool()
def HwdbgScriptRunScript()

@mcp.tool()
def ScriptEngineWrapperTestParserForHwdbg()

@mcp.tool()
def EnableTransparentMode()

@mcp.tool()
def DisableTransparentMode()

if __name__ == "__main__":
    mcp.run()
