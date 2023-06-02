package org.logdoc.sinks;

import com.typesafe.config.Config;
import org.logdoc.sdk.ConnectionType;
import org.logdoc.sdk.SinkPlugin;
import org.logdoc.structs.DataAddress;
import org.logdoc.structs.LogEntry;
import org.logdoc.structs.enums.Proto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;

import static org.logdoc.LogDocConstants.Fields.AppName;
import static org.logdoc.LogDocConstants.Fields.Ip;
import static org.logdoc.LogDocConstants.Fields.Level;
import static org.logdoc.LogDocConstants.Fields.Message;
import static org.logdoc.LogDocConstants.Fields.Pid;
import static org.logdoc.LogDocConstants.Fields.Source;
import static org.logdoc.LogDocConstants.logTimeFormat;
import static org.logdoc.helpers.Digits.getInt;
import static org.logdoc.helpers.Texts.notNull;

/**
 * Journald native protocol handler
 */
public class JournaldHandler implements SinkPlugin {
    private static final Logger logger = LoggerFactory.getLogger(JournaldHandler.class);
    private static final Set<ConnectionType> ct = Collections.singleton(new ConnectionType());

    static {
        ct.iterator().next().proto = Proto.UDP;
        ct.iterator().next().name = "Logdoc-Journald-Handler";
    }

    private Consumer<LogEntry> entryConsumer;
    private final ConcurrentMap<DataAddress, StreamData> flaps;

    public JournaldHandler() {
        flaps = new ConcurrentHashMap<>(0);
    }

    @Override
    public Set<ConnectionType> sinkTypes() {
        return ct;
    }

    @Override
    public void configure(final Config config, final Consumer<LogEntry> alien) {
        this.entryConsumer = entry -> {
            if (entry.field("MESSAGE") == null)
                return;

            final int priority = getInt(entry.field("PRIORITY"));
            final int facility = priority >> 3;
            final int level = priority - (facility << 3);

            try {
                entry.srcTime = LocalDateTime.parse(entry.fieldRemove("SYSLOG_TIMESTAMP"), DateTimeFormatter.ISO_OFFSET_DATE_TIME).format(logTimeFormat);
            } catch (final Exception e) {
                entry.srcTime = LocalDateTime.now().format(logTimeFormat);
                logger.error(e.getMessage(), e);
            }
            entry.field(AppName, notNull(entry.fieldRemove("SYSLOG_IDENTIFIER"), "unknown"));
            entry.field(Level, SyslogHandler.L2L.values()[level].ldl.name());
            entry.field(Pid, notNull(entry.fieldRemove("SYSLOG_PID"), "000"));
            entry.field(Source, "journald." + SyslogHandler.FACILITY.values()[facility].name() + "." + entry.field(AppName));
            entry.field(Message, entry.fieldRemove("MESSAGE"));

            alien.accept(entry);
        };
    }

    @Override
    public byte[] chunk(final byte[] data0, final DataAddress source) {
        if (!flaps.containsKey(source)) {
            flaps.put(source, new StreamData());
            flaps.get(source).entry.field(Ip, source.ip());
            flaps.get(source).entry.field("host", source.host());
        }

        StreamData sd = flaps.get(source);
        final byte[] data = sd.data == null ? data0 : new byte[sd.data.length + data0.length];
        if (sd.data != null) {
            System.arraycopy(sd.data, 0, data, 0, sd.data.length);
            System.arraycopy(data0, 0, data, sd.data.length, data0.length);
        }

        byte b, next;
        String tmp = null;
        long size = -1;

        for (int i = 0, from = -1; i < data.length; i++) {
            b = data[i];
            next = i < data.length - 1 ? data[i + 1] : -1;

            if (b == '\n') {
                if (from == -1) {
                    entryConsumer.accept(sd.entry);
                    if (next == -1) {
                        flaps.remove(source);
                        return null;
                    }

                    flaps.put(source, new StreamData());
                    flaps.get(source).entry.field(Ip, source.ip());
                    flaps.get(source).entry.field("host", source.host());
                    sd = flaps.get(source);
                    continue;
                }

                if (tmp == null) {
                    tmp = new String(Arrays.copyOfRange(data, from, i), StandardCharsets.UTF_8);

                    if (data.length - i > 9) {
                        final ByteBuffer bb = ByteBuffer.wrap(data, i, 8);
                        bb.order(ByteOrder.LITTLE_ENDIAN);
                        size = bb.getLong();
                        from = i + 1;

                        if (size + from > data.length) {
                            sd.data = Arrays.copyOfRange(data, i + 1, data.length);
                            return null;
                        }
                    } else {
                        sd.data = Arrays.copyOfRange(data, i + 1, data.length);
                        return null;
                    }
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

        return null;
    }

    private static class StreamData {
        private final LogEntry entry;
        private byte[] data;

        private StreamData() {
            entry = new LogEntry();
        }
    }
}
