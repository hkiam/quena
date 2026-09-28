// Interop corpus generator (test/build environment only – never shipped).
// For every XML file: XML --(Java FI encoder)--> .fi  and  .fi --(Java FI decoder)--> .expected.xml
// Plus programmatic documents exercising encoding algorithms and restricted alphabets.
import com.sun.xml.fastinfoset.sax.SAXDocumentParser;
import com.sun.xml.fastinfoset.sax.SAXDocumentSerializer;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.*;
import javax.xml.transform.sax.*;
import javax.xml.transform.stream.*;
import java.io.*;
import java.nio.file.*;
import org.xml.sax.helpers.AttributesImpl;

public class Gen {
    static void encode(Path xml, Path fi) throws Exception {
        try (OutputStream out = Files.newOutputStream(fi)) {
            SAXDocumentSerializer s = new SAXDocumentSerializer();
            s.setOutputStream(out);
            SAXParserFactory f = SAXParserFactory.newInstance();
            f.setNamespaceAware(true);
            javax.xml.parsers.SAXParser p = f.newSAXParser();
            p.setProperty("http://xml.org/sax/properties/lexical-handler", s);
            p.parse(xml.toFile(), s);
        }
    }

    static void decode(Path fi, Path xml) throws Exception {
        SAXTransformerFactory tf = (SAXTransformerFactory) TransformerFactory.newInstance();
        TransformerHandler th = tf.newTransformerHandler();
        th.getTransformer().setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        try (InputStream in = Files.newInputStream(fi); OutputStream out = Files.newOutputStream(xml)) {
            th.setResult(new StreamResult(out));
            SAXDocumentParser p = new SAXDocumentParser();
            p.setContentHandler(th);
            p.setLexicalHandler(th);
            p.parse(in);
        }
    }

    static void primitives(Path fi) throws Exception {
        try (OutputStream out = Files.newOutputStream(fi)) {
            SAXDocumentSerializer s = new SAXDocumentSerializer();
            s.setOutputStream(out);
            AttributesImpl none = new AttributesImpl();
            s.startDocument();
            s.startElement("", "primitives", "primitives", none);
            s.startElement("", "ints", "ints", none);
            s.ints(new int[]{1, -2, 2147483647, -2147483648, 0}, 0, 5);
            s.endElement("", "ints", "ints");
            s.startElement("", "shorts", "shorts", none);
            s.shorts(new short[]{1, -1, 32767}, 0, 3);
            s.endElement("", "shorts", "shorts");
            s.startElement("", "longs", "longs", none);
            s.longs(new long[]{9223372036854775807L, -42L}, 0, 2);
            s.endElement("", "longs", "longs");
            s.startElement("", "booleans", "booleans", none);
            s.booleans(new boolean[]{true, false, true, true, false, false, true, false, true, true, true}, 0, 11);
            s.endElement("", "booleans", "booleans");
            s.startElement("", "bytes", "bytes", none);
            s.bytes(new byte[]{0, 1, 2, (byte) 0xFE, (byte) 0xFF, 65, 66}, 0, 7);
            s.endElement("", "bytes", "bytes");
            s.startElement("", "uuids", "uuids", none);
            s.uuids(new long[]{0x0123456789abcdefL, 0xfedcba9876543210L}, 0, 2);
            s.endElement("", "uuids", "uuids");
            s.startElement("", "numeric", "numeric", none);
            char[] n = "3.14159E-10 -42".toCharArray();
            s.numericCharacters(n, 0, n.length);
            s.endElement("", "numeric", "numeric");
            s.startElement("", "date", "date", none);
            char[] d = "2026-09-28T19:14:48Z".toCharArray();
            s.dateTimeCharacters(d, 0, d.length);
            s.endElement("", "date", "date");
            s.endElement("", "primitives", "primitives");
            s.endDocument();
        }
    }

    public static void main(String[] a) throws Exception {
        Path dir = Paths.get(a[0]);
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir.resolve("xml"), "*.xml")) {
            for (Path x : ds) {
                String base = x.getFileName().toString().replace(".xml", "");
                Path fi = dir.resolve("corpus").resolve(base + ".fi");
                encode(x, fi);
                decode(fi, dir.resolve("corpus").resolve(base + ".expected.xml"));
                System.out.println("encoded " + base + " (" + Files.size(x) + " -> " + Files.size(fi) + " bytes)");
            }
        }
        Path pf = dir.resolve("corpus").resolve("primitives.fi");
        primitives(pf);
        decode(pf, dir.resolve("corpus").resolve("primitives.expected.xml"));
        System.out.println("encoded primitives");
    }
}
