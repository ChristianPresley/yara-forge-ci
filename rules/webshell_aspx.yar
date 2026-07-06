/*
    Detection idea: ASPX / .NET webshells that expose a runtime code-execution sink
    (Process.Start, eval-style JScript, or the classic "China Chopper" one-liner)
    driven by request input. China Chopper's minimal server-side stub is a well
    known IOC: <%@Page Language="Jscript"%>...eval(Request.Item[...]).

    Performance notes:
    - Uses the distinctive server-page directive plus a sink; avoids matching on
      generic ASP.NET markup.
    - "Request.Item" / "Request.Form" are specific enough to be useful atoms.
*/

rule Webshell_ASPX_CodeExec
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects ASPX/JScript webshells (incl. China Chopper) executing request-supplied code"
        reference     = "https://attack.mitre.org/techniques/T1505/003/"
        mitre_attack  = "T1505.003"
        severity      = "high"
        version       = "1.0"

    strings:
        // Server-side page markers
        $page1 = "<%@ Page Language=" nocase ascii
        $page2 = "<%@Page Language=" nocase ascii
        $page3 = "runat=\"server\"" nocase ascii
        $page4 = "<script runat=\"server\"" nocase ascii

        // Execution sinks
        $sink1 = /\beval\s*\(\s*Request/ nocase ascii     // China Chopper core
        $sink2 = "Process.Start" nocase ascii
        $sink3 = "System.Diagnostics.Process" nocase ascii
        $sink4 = "JScript.Compile" nocase ascii

        // Request-borne input
        $req1 = "Request.Item" nocase ascii
        $req2 = "Request.Form" nocase ascii
        $req3 = "Request.QueryString" nocase ascii

    condition:
        1 of ($page*)
        and 1 of ($sink*)
        and 1 of ($req*)
}
