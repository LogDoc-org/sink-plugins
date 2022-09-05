package org.logdoc.sinks;

import com.typesafe.config.Config;
import org.logdoc.sdk.ConnectionType;
import org.logdoc.sdk.SinkPlugin;
import org.logdoc.structs.DataAddress;
import org.logdoc.structs.LogEntry;
import org.logdoc.structs.enums.Proto;
import org.logdoc.utils.Tools;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.function.Consumer;

import static org.logdoc.LogDocConstants.Fields.Ip;

/**
 * Logdoc native protocol handler (HTTP)
 */
public class LogdocHttpHandler implements SinkPlugin {
    private static final Set<ConnectionType> ids = Collections.singleton(new ConnectionType(Proto.HTTP, "Logdoc-Logback-Http-Handler"));
    private static final byte[] okBytes = "HTTP/1.1 200\r\n\r\n".getBytes(StandardCharsets.UTF_8);

    private long maxRequestSize = 1024 * 128;

    private Consumer<LogEntry> consumer;

    @Override
    public void configure(final Config config, final Consumer<LogEntry> consumer) {
        this.consumer = consumer;
        if (config == null)
            return;

        if (config.hasPath("max_request_size"))
            try {
                final long v = config.getLong("max_request_size");

                if (v > 0)
                    maxRequestSize = v;
            } catch (final Exception ignore) {}
    }

    @Override
    public byte[] chunk(final byte[] data, final DataAddress dataAddress) {
        int i = 0;

        for (; i < data.length; i++)
            if (data[i] == '\n' && i < data.length - 1 && data[i + 1] == '\n') {
                i += 2;
                break;
            }

        byte b;
        String tmp = null;
        final StreamData sd = new StreamData();
        sd.entry = new LogEntry();
        sd.entry.field(Ip, dataAddress.ip());
        sd.entry.field("host", dataAddress.host());

        for (int from = -1, size = -1; i < data.length; i++) {
            b = data[i];

            if (b == '\n') {
                if (from == -1) { // конец entry
                    consumer.accept(sd.entry);
                    break;
                }

                if (tmp == null) { // название поля, дальше будет размер - инт в 4 байтах
                    tmp = new String(Arrays.copyOfRange(data, from, i), StandardCharsets.UTF_8);

                    if (data.length - i > 5) {
                        size = Tools.asInt(new byte[]{data[++i], data[++i], data[++i], data[++i]}) - 1;
                        from = i + 1;

                        if (size + from > data.length)
                            break;
                    } else
                        break;
                } else { // значение поля
                    sd.entry.field(tmp, new String(Arrays.copyOfRange(data, from, i), StandardCharsets.UTF_8));
                    from = -1;
                    tmp = null;
                }
            } else if (b == '=') {
                if (tmp == null && from != -1) { // значение поля
                    tmp = new String(Arrays.copyOfRange(data, from, i), StandardCharsets.UTF_8);
                    from = i + 1;
                }
            } else {
                if (from == -1)
                    from = i;
                else if (size != -1 && from + size == i && tmp != null) {
                    sd.entry.field(tmp, new String(Arrays.copyOfRange(data, from, i + 1), StandardCharsets.UTF_8));
                    from = -1;
                    size = -1;
                    tmp = null;
                }
            }
        }

        return okBytes;
    }

    @Override
    public long maxReadBuf() {
        return maxRequestSize;
    }

    private static class StreamData {
        private LogEntry entry;
    }

    @Override
    public Set<ConnectionType> sinkTypes() {
        return ids;
    }
}
