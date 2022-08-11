package org.logdoc.sinks;

import com.typesafe.config.Config;
import org.logdoc.sdk.ConnectionType;
import org.logdoc.sdk.SinkPlugin;
import org.logdoc.structs.DataAddress;
import org.logdoc.structs.LogEntry;
import org.logdoc.structs.enums.LogLevel;
import org.logdoc.structs.enums.Proto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.function.Consumer;

import static org.logdoc.LogDocConstants.Fields.AppName;
import static org.logdoc.LogDocConstants.Fields.Ip;
import static org.logdoc.LogDocConstants.Fields.Level;
import static org.logdoc.LogDocConstants.Fields.Message;
import static org.logdoc.LogDocConstants.Fields.Pid;
import static org.logdoc.LogDocConstants.Fields.Source;
import static org.logdoc.LogDocConstants.Fields.TimeSrc;
import static org.logdoc.LogDocConstants.logTimeFormat;

public class PythonPlugin implements SinkPlugin {
    private static final Set<ConnectionType> ct = new HashSet<>(2);
    private static final byte[] delimiter = {0, 0, 0};
    //    private static final int emptyString = 78; // N - push None
    private static final int int1Byte = 75; // K - push 1-byte unsigned int
    private static final int int2Bytes = 77; // M - push 2-byte unsigned int
    private static final int int4Bytes = 74; // J - four-byte signed int
    private static final int float8Bytes = 71; // G - push float; arg is 8-byte float encoding
    private static final int longAsString = 76; // L - push long; decimal string argument
    private static final int countedString = 88; // X - counted UTF-8 string argument

    static {
        final ConnectionType tcp = new ConnectionType();
        tcp.proto = Proto.TCP;
        tcp.name = "Logdoc-Python-Tcp-Handler";
        final ConnectionType udp = new ConnectionType();
        udp.proto = Proto.UDP;
        udp.name = "Logdoc-Python-Udp-Handler";

        ct.add(tcp);
        ct.add(udp);
    }

    private Consumer<LogEntry> entryConsumer;

    @Override
    public synchronized void configure(final Config config, final Consumer<LogEntry> entryConsumer) {
        this.entryConsumer = entryConsumer;
    }

    @Override
    public Set<ConnectionType> sinkTypes() {
        return ct;
    }

    @Override
    public byte[] chunk(byte[] data0, DataAddress source) {
        if (data0 == null)
            return null;

        final LogEntry entry = new LogEntry();
        entry.field(Ip, source.ip());
        entry.field("host", source.host());

        byte b, valueType;
        int argLength;
        boolean readKey = true;
        String key = "", value;

        final Map<String, String> stringMap = new HashMap<>();

        for (int i = 0; i < data0.length; i++) {
            b = data0[i];

            if (b == countedString && Arrays.equals(Arrays.copyOfRange(data0, i + 2, i + 5), delimiter)) {
                argLength = (int) data0[i + 1] < 0 ? (data0[i + 1] & 0xff) : data0[i + 1];
                if (readKey) {
                    key = new String(Arrays.copyOfRange(data0, i + 5, i + 5 + argLength), StandardCharsets.UTF_8);
                    i = i + 5 + argLength;
                    valueType = data0[i + 2];
                    final int valueStartPosition = i + 3;

                    switch (valueType) {
                        case int1Byte:
                            value = String.valueOf(data0[valueStartPosition] < 0 ? (data0[valueStartPosition] & 0xff) : data0[valueStartPosition]);
                            stringMap.put(key, value);
                            break;
                        case int2Bytes:
                            value = String.valueOf((data0[valueStartPosition + 1] << 8) | (data0[valueStartPosition] & 0xFF));
                            stringMap.put(key, value);
                            break;
                        case int4Bytes:
                            value = String.valueOf(ByteBuffer.wrap(Arrays.copyOfRange(data0, valueStartPosition, i + 7)).order(ByteOrder.LITTLE_ENDIAN).getInt());
                            stringMap.put(key, value);
                            break;
                        case float8Bytes:
                            value = String.format("%f", ByteBuffer.wrap(Arrays.copyOfRange(data0, valueStartPosition, i + 11)).getDouble());
                            stringMap.put(key, value);
                            i = i + 10;
                            break;
                        case longAsString:
                            value = "";
                            for (int j = valueStartPosition; j < i + 22; j++) {
                                if (data0[j] == countedString)
                                    break;

                                if (data0[j] == longAsString) {
                                    value = new String(Arrays.copyOfRange(data0, valueStartPosition, j));
                                    break;
                                }
                            }
                            stringMap.put(key, value);
                            break;
                        case countedString:
                            readKey = false;
                            break;
                        default:
                            value = "";
                            stringMap.put(key, value);
                    }
                } else {
                    value = new String(Arrays.copyOfRange(data0, i + 5, i + 5 + argLength), StandardCharsets.UTF_8);
                    i = i + 5 + argLength;
                    readKey = true;
                    stringMap.put(key, value);
                }
            }
        }
        for (final Map.Entry<String, String> me : stringMap.entrySet())
            entry.field(me.getKey(), me.getValue());

        entry.field(TimeSrc, date(stringMap.get("created"), entry.rcvTime));
        entry.field(Pid, stringMap.get("process"));
        entry.field(Source, stringMap.get("processName") + " " + stringMap.get("filename"));
        entry.field(Message, stringMap.get("msg"));
        entry.field(AppName, stringMap.get("module"));
        entry.field(Level, L2L.valueOf(stringMap.get("levelname")).ldl.name());

        entryConsumer.accept(entry);

        return null;
    }

    private String date(final String inDate, final String defaultDate) {
        try {
            return LocalDateTime.ofInstant(Instant.ofEpochMilli((long) (Double.parseDouble(inDate) * 1000)), TimeZone.getTimeZone("UTC").toZoneId()).format(logTimeFormat);
        } catch (final Exception e) {
            return defaultDate;
        }
    }

    enum L2L {
        CRITICAL(LogLevel.SEVERE), ERROR(LogLevel.ERROR), WARNING(LogLevel.WARN), INFO(LogLevel.INFO), DEBUG(LogLevel.DEBUG), NOTSET(LogLevel.LOG);

        public final LogLevel ldl;

        L2L(final LogLevel ldl) {
            this.ldl = ldl;
        }
    }
}
