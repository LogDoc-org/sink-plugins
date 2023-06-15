package org.logdoc.sinks;

import com.typesafe.config.Config;
import org.logdoc.sdk.ConnectionType;
import org.logdoc.sdk.SinkPlugin;
import org.logdoc.structs.DataAddress;
import org.logdoc.structs.LogEntry;
import org.logdoc.structs.enums.Proto;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import static org.logdoc.LogDocConstants.Fields.Ip;
import static org.logdoc.helpers.Texts.isEmpty;

/**
 * Logdoc native protocol handler (HTTP)
 */
public class LogdocHttpHandler implements SinkPlugin {
    private static final Set<ConnectionType> ids = Collections.singleton(new ConnectionType(Proto.HTTP, "Logdoc-Logback-Http-Handler"));
    private static final byte[] okBytes = "HTTP/1.1 204 No Content\r\n\r\n".getBytes(StandardCharsets.UTF_8);

    private long maxRequestSize = 1024 * 128;

    private Consumer<LogEntry> consumer;

    @Override
    public boolean isDeterminated() {
        return true;
    }

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

        // skip all http data, look for double crlf
        for (; i < data.length - 4; i++)
            if (data[i] == '\r' &&
                    data[i + 1] == '\n' &&
                    data[i + 2] == '\r' &&
                    data[i + 3] == '\n') {
                i += 4;
                break;
            }

        if (i == 0)
            return okBytes;

        final String body = new String(Arrays.copyOfRange(data, i, data.length), StandardCharsets.UTF_8);
        final String[] fields = body.split(Pattern.quote("&"));

        final LogEntry entry = new LogEntry();

        String[] pair;
        for (final String field : fields)
            try {
                pair = field.split(Pattern.quote("="), 2);

                if (pair.length == 2)
                    entry.field(pair[0], URLDecoder.decode(pair[1], "UTF-8"));
            } catch (final Exception ignore) {}

        if (!isEmpty(entry.entry)) {
            entry.field(Ip, dataAddress.ip());
            entry.field("host", dataAddress.host());
            consumer.accept(entry);
        }

        return okBytes;
    }

    @Override
    public long maxReadBuf() {
        return maxRequestSize;
    }

    @Override
    public Set<ConnectionType> sinkTypes() {
        return ids;
    }
}
