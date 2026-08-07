import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.api.vapt.parser import parse_upload


def test_parse_nessus_xml_extracts_mac_address_from_host_properties_tag_value():
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


def test_parse_nessus_xml_extracts_mac_address_from_host_properties_text_node():
    content = b"""
    <NessusClientData_v2>
      <Report>
        <ReportHost name="192.168.1.10">
          <HostProperties>
            <tag name="mac address">00:11:22:33:44:55</tag>
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


def test_parse_nessus_xml_extracts_mac_address_from_property_element():
    content = b"""
    <NessusClientData_v2>
      <Report>
        <ReportHost name="192.168.1.10">
          <HostProperties>
            <property name="mac address" value="00:11:22:33:44:55" />
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
