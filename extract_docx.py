import zipfile
import xml.etree.ElementTree as ET

def get_docx_text(path):
    document = zipfile.ZipFile(path)
    xml_content = document.read('word/document.xml')
    document.close()
    tree = ET.XML(xml_content)
    
    WORD_NAMESPACE = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
    PARA = WORD_NAMESPACE + 'p'
    TEXT = WORD_NAMESPACE + 't'
    
    paragraphs = []
    for paragraph in tree.iter(PARA):
        texts = [node.text
                 for node in paragraph.iter(TEXT)
                 if node.text]
        if texts:
            paragraphs.append(''.join(texts))
    return '\n\n'.join(paragraphs)

try:
    text = get_docx_text(r'd:\freelansing\time pass\chess extention\Formatted_API_Documentation.docx')
    with open(r'd:\freelansing\time pass\chess extention\api_docs.txt', 'w', encoding='utf-8') as f:
        f.write(text)
except Exception as e:
    with open(r'd:\freelansing\time pass\chess extention\api_docs.txt', 'w', encoding='utf-8') as f:
        f.write("Error: " + str(e))
