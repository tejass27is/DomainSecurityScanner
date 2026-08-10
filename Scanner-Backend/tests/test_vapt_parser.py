from app.api.vapt.parser import parse_upload


def test_parse_csv_supports_vapt_specific_columns():
    content = (
        "CVE,CVSS Base Score,Risk,Status,Host,MAC Address,Hostname,Operating System,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Remarks\n"
        "CVE-2024-1234,7.5,High,Pending,192.168.1.10,00:11:22:33:44:55,server1,Ubuntu 22.04,TCP,443,OpenSSL issue,foo,bar,baz,https://example.com,output,Needs review\n"
    ).encode("utf-8")

    raw, source_tool, file_format = parse_upload(content, "sample.csv")

    assert file_format == "csv"
    assert source_tool == "generic"
    assert raw[0]["cves"] == ["CVE-2024-1234"]
    assert raw[0]["severity_label"] == "high"
    assert raw[0]["status"] == "pending"
    assert raw[0]["comment"] == "Needs review"
    assert raw[0]["mac_address"] == "00:11:22:33:44:55"


def test_parse_nessus_xml_extracts_mac_address():
    content = b"""
    <NessusClientData_v2>
      <Report>
        <ReportHost name="192.168.1.10">
          <HostProperties>
            <tag name="mac address" value="00:11:22:33:44:55" />
          </HostProperties>
          <ReportItem port="443" protocol="tcp" severity="3" pluginName="Test plugin">
            <description>Test</description>
            <plugin_output>Output</plugin_output>
          </ReportItem>
        </ReportHost>
      </Report>
    </NessusClientData_v2>
    """
    raw, source_tool, file_format = parse_upload(content, "sample.nessus")

    assert file_format == "xml"
    assert source_tool == "nessus"
    assert raw[0]["mac_address"] == "00:11:22:33:44:55"
