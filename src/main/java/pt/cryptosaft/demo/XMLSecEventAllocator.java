package pt.cryptosaft.demo;

import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;
import javax.xml.stream.util.XMLEventAllocator;
import javax.xml.stream.util.XMLEventConsumer;

/**
 * <p></p>
 * An extended XMLEventAllocator to collect namespaces and C14N relevant attributes
 *
 */
public class XMLSecEventAllocator implements XMLEventAllocator {

    private XMLEventAllocator xmlEventAllocator;
    private XMLSecStartElement parentXmlSecStartElement;

    public XMLSecEventAllocator() throws Exception {
        xmlEventAllocator = com.ctc.wstx.evt.DefaultEventAllocator.getDefaultInstance();
    }

    @Override
    public XMLEventAllocator newInstance() {
        try {
            return new XMLSecEventAllocator();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public XMLEvent allocate(XMLStreamReader xmlStreamReader) throws XMLStreamException {
        XMLSecEvent xmlSecEvent = XMLSecEventFactory.allocate(xmlStreamReader, parentXmlSecStartElement);
        switch (xmlSecEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                parentXmlSecStartElement = (XMLSecStartElement) xmlSecEvent;
                break;
            case XMLStreamConstants.END_ELEMENT:
                if (parentXmlSecStartElement != null) {
                    parentXmlSecStartElement = parentXmlSecStartElement.getParentXMLSecStartElement();
                }
                break;
        }
        return xmlSecEvent;
    }

    @Override
    public void allocate(XMLStreamReader reader, XMLEventConsumer consumer) throws XMLStreamException {
        xmlEventAllocator.allocate(reader, consumer);
    }
}