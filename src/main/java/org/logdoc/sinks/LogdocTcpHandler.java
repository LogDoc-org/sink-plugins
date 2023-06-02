package org.logdoc.sinks;

import com.typesafe.config.Config;
import org.logdoc.sdk.ConnectionType;
import org.logdoc.sdk.SinkPlugin;
import org.logdoc.structs.DataAddress;
import org.logdoc.structs.LogEntry;
import org.logdoc.structs.enums.Proto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;

import static org.logdoc.LogDocConstants.Fields.Ip;
import static org.logdoc.LogDocConstants.header;
import static org.logdoc.helpers.BinFlows.asInt;


/**
 * Logdoc native protocol handler (TCP)
 */
public class LogdocTcpHandler implements SinkPlugin {
    private static final Set<ConnectionType> ct;

    static {
        final ConnectionType ct0 = new ConnectionType();
        ct0.proto = Proto.TCP;
        ct0.name = "Logdoc-Logback-Tcp-Handler";

        ct = Collections.singleton(ct0);
    }

    private final ConcurrentMap<DataAddress, StreamData> flaps;
    private Consumer<LogEntry> entryConsumer;

    public LogdocTcpHandler() {
        flaps = new ConcurrentHashMap<>(8);
    }

    @Override
    public Set<ConnectionType> sinkTypes() {
        return ct;
    }

    @Override
    public void configure(final Config config, final Consumer<LogEntry> entryConsumer) {
        this.entryConsumer = entryConsumer;
    }

    @Override
    public byte[] chunk(final byte[] data0, final DataAddress source) {
        if (data0 == null)
            return null;

        StreamData sd;
        if ((sd = flaps.get(source)) == null) {
            sd = new StreamData();
            sd.entry = new LogEntry();
            sd.entry.field(Ip, source.ip());
            sd.entry.field("host", source.host());

            flaps.put(source, sd);
        }

        final byte[] data = sd.tail == null ? data0 : new byte[sd.tail.length + data0.length];
        if (sd.tail != null) {
            System.arraycopy(sd.tail, 0, data, 0, sd.tail.length);
            System.arraycopy(data0, 0, data, sd.tail.length, data0.length);
            sd.tail = null;
        }

        int j = -1, i = 0;
        byte b;
        String tmp = null;

        for (int size = -1; i < data.length; i++) {
            b = data[i];

            if (sd.state == STATE.head0) {
                if (b == header[0])
                    sd.state = STATE.head1;

                j = -1;
                continue;
            } else if (sd.state == STATE.head1) {
                sd.state = b == header[1] ? STATE.Void : STATE.head0;
                j = -1;
                continue;
            }

            if (b == '\n' && sd.state != STATE.valueS) {
                if (sd.state == STATE.Void) {
                    entryConsumer.accept(sd.entry);

                    if (i < data.length - 1) {
                        flaps.put(source, new StreamData());
                        flaps.get(source).entry = new LogEntry();
                        flaps.get(source).entry.field(Ip, source.ip());
                        flaps.get(source).entry.field("host", source.host());
                        sd = flaps.get(source);
                        j = i + 1;
                    } else
                        return null;
                } else if (sd.state == STATE.value) {
                    sd.entry.field(tmp, new String(Arrays.copyOfRange(data, j, i), StandardCharsets.UTF_8));
                    sd.state = STATE.Void;
                    j = -1;
                } else if (sd.state == STATE.name) {
                    tmp = new String(Arrays.copyOfRange(data, j, i), StandardCharsets.UTF_8);
                    sd.state = STATE.size;
                    j = i + 1;
                }
            } else if (b == '=' && sd.state == STATE.name) {
                tmp = new String(Arrays.copyOfRange(data, j, i), StandardCharsets.UTF_8);
                sd.state = STATE.value;
                j = i + 1;
            } else {
                if (j == -1)
                    j = i;

                if (sd.state == STATE.Void)
                    sd.state = STATE.name;

                if (sd.state == STATE.size && i == j + 4) {
                    size = asInt(Arrays.copyOfRange(data, j, i));
                    sd.state = STATE.valueS;
                    j = i;
                } else if (sd.state == STATE.valueS && i == j + size - 1) {
                    sd.entry.field(tmp, new String(Arrays.copyOfRange(data, j, i + 1), StandardCharsets.UTF_8));

                    j = i + 1;
                    sd.state = STATE.Void;
                }
            }
        }

        if (j != -1 && j < data.length - 1)
            sd.tail = Arrays.copyOfRange(data, j, data.length);

        return null;
    }

    private static class StreamData {
        private LogEntry entry;
        private byte[] tail;

        private STATE state = STATE.head0;
    }

    private enum STATE {head0, head1, name, size, valueS, value, Void}
}
