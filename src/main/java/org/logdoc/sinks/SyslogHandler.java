package org.logdoc.sinks;

import com.typesafe.config.Config;
import org.logdoc.sdk.ConnectionType;
import org.logdoc.sdk.SinkPlugin;
import org.logdoc.structs.DataAddress;
import org.logdoc.structs.LogEntry;
import org.logdoc.structs.enums.LogLevel;
import org.logdoc.structs.enums.Proto;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.logdoc.LogDocConstants.Fields.AppName;
import static org.logdoc.LogDocConstants.Fields.Ip;
import static org.logdoc.LogDocConstants.Fields.Pid;
import static org.logdoc.LogDocConstants.logTimeFormat;
import static org.logdoc.helpers.Digits.getInt;
import static org.logdoc.helpers.Texts.isEmpty;
import static org.logdoc.helpers.Texts.notNull;

/**
 * (r)Syslog native protocol handler
 */
public class SyslogHandler implements SinkPlugin {
    private static final String bsdDateTimePattern = "MMM [ ][d][d] HH:mm:ss[ yyyy]";
    private static final Set<ConnectionType> ct = new HashSet<>(2);

    static {
        final ConnectionType tcp = new ConnectionType();
        tcp.proto = Proto.TCP;
        tcp.name = "Logdoc-Syslog-Tcp-Handler";
        final ConnectionType udp = new ConnectionType();
        udp.proto = Proto.UDP;
        udp.name = "Logdoc-Syslog-Udp-Handler";

        ct.add(tcp);
        ct.add(udp);
    }

    private final ConcurrentMap<DataAddress, StreamData> flaps;
    private final AtomicReference<DateTimeFormatter> format;
    private final Set<Byte> delimiters;
    private Consumer<LogEntry> entryConsumer;

    public SyslogHandler() {
        this.delimiters = new HashSet<>(2);
        this.format = new AtomicReference<>(DateTimeFormatter.ofPattern(bsdDateTimePattern, Locale.forLanguageTag("en")));
        flaps = new ConcurrentHashMap<>(0);

        format.set(DateTimeFormatter.ofPattern(bsdDateTimePattern, Locale.ENGLISH));
        delimiters.add((byte) '\r');
        delimiters.add((byte) '\n');
    }

    @Override
    public synchronized void configure(final Config config, final Consumer<LogEntry> entryConsumer) {
        this.entryConsumer = entryConsumer;

        if (config.hasPath("date_locale"))
            format.set(DateTimeFormatter.ofPattern(bsdDateTimePattern, Locale.forLanguageTag(notNull(config.getString("date_locale"), "en"))));

        if (config.hasPath("tcp_delimiters"))
            try {
                delimiters.clear();
                config.getIntList("tcp_delimiters")
                        .forEach(d -> delimiters.add((byte) (int) d));
            } catch (final Exception ignore) {
                delimiters.clear();
                delimiters.add((byte) '\r');
                delimiters.add((byte) '\n');
            }
    }

    @Override
    public Set<ConnectionType> sinkTypes() {
        return ct;
    }

    @Override
    public byte[] chunk(final byte[] data0, final DataAddress source) {
        if (!flaps.containsKey(source)) {
            flaps.put(source, new StreamData());
            flaps.get(source).src = source;
            flaps.get(source).entry = new LogEntry();
            flaps.get(source).entry.field(Ip, source.ip());
            flaps.get(source).entry.field("host", source.host());
        }

        StreamData sd = flaps.get(source);
        final byte[] data = sd.data == null ? data0 : new byte[sd.data.length + data0.length];
        if (sd.data != null) {
            System.arraycopy(sd.data, 0, data, 0, sd.data.length);
            System.arraycopy(data0, 0, data, sd.data.length, data0.length);
        }

        if (sd.priority == -1)
            priority(data, sd);
        else if (sd.bsd == null)
            logType(0, data, sd);
        else if (sd.bsd) {
            if (sd.entry.srcTime == null)
                bsdDate(0, data, sd);
            else if (sd.entry.field("domain") == null)
                bsdDomain(0, data, sd);
            else
                body(0, data, sd);
        } else {
            if (sd.entry.srcTime == null)
                date(0, data, sd);
            else if (sd.entry.field("domain") == null)
                domain(0, data, sd);
            else if (sd.entry.appName == null)
                app(0, data, sd);
            else if (sd.entry.pid == null)
                pid(0, data, sd);
            else if (sd.entry.field("msgId") == null)
                msgId(0, data, sd);
            else if (sd.structs == null)
                structs(0, data, sd);
            else
                body(0, data, sd);
        }

        return null;
    }

    private void priority(final byte[] data, final StreamData sd) {
        for (int from = 0, i = 0; i < data.length; i++)
            if (data[i] == '<')
                from = i + 1;
            else if (data[i] == '>') {
                sd.priority = getInt(new String(Arrays.copyOfRange(data, from, i)));
                logType(i + 1, data, sd);
                break;
            }

    }

    private void logType(final int idx, final byte[] data, final StreamData sd) {
        sd.bsd = !Character.isDigit(data[idx]);
        if (sd.bsd)
            bsdDate(idx, data, sd);
        else {
            sd.version = data[idx];
            date(idx + 1, data, sd);
        }
    }

    private void date(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        for (; i < data.length; i++)
            if (Character.isSpaceChar(data[i])) {
                sd.entry.srcTime = LocalDateTime.parse(new String(Arrays.copyOfRange(data, idx, i), StandardCharsets.UTF_8), DateTimeFormatter.ISO_OFFSET_DATE_TIME).format(logTimeFormat);
                domain(i + 1, data, sd);
                return;
            }

        sd.data = Arrays.copyOfRange(data, idx, data.length);
    }

    private void domain(final int idx, final byte[] data, final StreamData sd) {
        for (int i = idx; i < data.length; i++)
            if (Character.isSpaceChar(data[i])) {
                sd.entry.field("domain", new String(Arrays.copyOfRange(data, idx, i)));
                app(i + 1, data, sd);
                return;
            }

        sd.data = Arrays.copyOfRange(data, idx, data.length);
    }

    private void app(final int idx, final byte[] data, final StreamData sd) {
        for (int i = idx; i < data.length; i++)
            if (data[i] == '-' || Character.isSpaceChar(data[i])) {
                sd.entry.field(AppName, new String(Arrays.copyOfRange(data, idx, i), StandardCharsets.UTF_8));
                pid(i + 1, data, sd);
                return;
            }

        sd.data = Arrays.copyOfRange(data, idx, data.length);
    }

    private void pid(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        for (; i < data.length; i++)
            if (data[i] == '-' || Character.isSpaceChar(data[i])) {
                sd.entry.field(Pid, new String(Arrays.copyOfRange(data, idx, i), StandardCharsets.UTF_8));
                msgId(i + 1, data, sd);
                return;
            }

        sd.data = Arrays.copyOfRange(data, idx, data.length);
    }

    private void msgId(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        for (; i < data.length; i++)
            if (data[i] == '-' || Character.isSpaceChar(data[i])) {
                sd.entry.field("msgId", new String(Arrays.copyOfRange(data, idx, i), StandardCharsets.UTF_8));
                structs(i + 1, data, sd);
                return;
            }

        sd.data = Arrays.copyOfRange(data, idx, data.length);
    }

    private void structs(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        if (data[i] == '[') {
            sd.structs = new ArrayList<>(0);

            struct(i, data, sd);
        } else {
            sd.structs = Collections.emptyList();

            body(idx + (data[i] == '-' ? 1 : 0), data, sd);
        }
    }

    private void struct(final int idx, final byte[] data, final StreamData sd) {
        final SysStruct struct = new SysStruct();
        int left = -1, right = -1;
        for (int i = idx; i < data.length; i++) {
            if (data[i] == '[')
                left = i;
            else if (data[i] == ']')
                right = i;

            if (left >= 0 && right >= 1)
                break;
        }

        if (left == -1 || right == -1) {
            body(idx, data, sd);
            return;
        }

        int from = left + 1;
        int till = right - 1;

        for (int i = from + 1; i < till; i++)
            if (Character.isWhitespace(data[i])) {
                till = i;
                break;
            }

        struct.name = new String(Arrays.copyOfRange(data, from, till), StandardCharsets.US_ASCII).trim();

        if (till + 1 != right)
            do {
                from = till;

                do {from++;} while (Character.isWhitespace(data[from]));

                for (till = from; till < data.length; till++)
                    if (data[till] == '=')
                        break;
                if (till < data.length - 1 && data[till + 1] == '"') {
                    struct.tmp = new String(Arrays.copyOfRange(data, from, till), StandardCharsets.US_ASCII).trim();

                    from = till + 2;
                    for (till = from; till < data.length; till++)
                        if (data[till] == '"')
                            break;

                    struct.put(new String(Arrays.copyOfRange(data, from, till), StandardCharsets.US_ASCII).trim());
                    sd.structs.add(struct);
                }
            } while (right > ++till && Character.isWhitespace(data[till]));


        if (struct.isEmpty()) {
            sd.structs.remove(struct);
            body(idx, data, sd);
        }

        do {right++;} while (right < data.length - 1 && Character.isWhitespace(data[right]));

        if (data[right] == '[')
            struct(right, data, sd);
        else
            body(right, data, sd);
    }

    private void bsdDate(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        if (data.length <= i + 16) {
            sd.data = Arrays.copyOfRange(data, i, data.length);
            return;
        }

        sd.entry.srcTime = LocalDateTime.parse(new String(Arrays.copyOfRange(data, idx, idx + 16)) + LocalDateTime.now().getYear(), format.get()).format(logTimeFormat);

        bsdDomain(i + 16, data, sd);
    }

    private void bsdDomain(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        for (; i < data.length; i++)
            if (Character.isWhitespace(data[i])) {
                sd.entry.field("domain", new String(Arrays.copyOfRange(data, idx, i)));
                bsdApp(i, data, sd);
                return;
            }

        sd.data = Arrays.copyOfRange(data, idx, data.length);
    }

    private void bsdApp(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        for (; i < data.length; i++)
            if (data[i] == ':' || Character.isSpaceChar(data[i])) {
                sd.entry.field(AppName, new String(Arrays.copyOfRange(data, idx, i), StandardCharsets.UTF_8));
                structs(i + 1, data, sd);
                return;
            }

        sd.data = Arrays.copyOfRange(data, idx, data.length);
    }

    private void body(final int idx, final byte[] data, final StreamData sd) {
        int i = idx;
        while (i < data.length - 1 && Character.isWhitespace(data[i])) i++;

        final int from = i;
        int till = data.length;
        if (sd.src.sink.type.proto != Proto.UDP && !delimiters.isEmpty())
            for (; i < data.length; i++)
                if (delimiters.contains(data[i])) {
                    till = i;
                    break;
                }

        sd.entry.entry = new String(Arrays.copyOfRange(data, from, till), StandardCharsets.UTF_8).trim();
        final int facility = sd.priority >> 3;
        final int level = sd.priority - (facility << 3);
        sd.entry.level = L2L.values()[level].ldl;
        sd.entry.field("priority", String.valueOf(sd.priority));
        sd.entry.field("facility", String.valueOf(facility));

        final int bi = sd.entry.field(AppName).indexOf('[');
        if (bi > 0) {
            sd.entry.field("instId", sd.entry.field(AppName).substring(bi + 1).replace("]", ""));
            sd.entry.field(AppName, sd.entry.field(AppName).substring(0, bi));
        }

        sd.entry.source = "syslog." + FACILITY.values()[facility].name() + "." + notNull(sd.entry.field(AppName), "undef-" + sd.entry.pid);

        if (!isEmpty(sd.structs))
            sd.structs.forEach(s -> {
                sd.entry.field("struct-id-" + s.name, s.name);
                s.forEach((k, v) -> sd.entry.field(k, v));
            });

        if (sd.version > 0) sd.entry.field("version", String.valueOf(sd.version));

        entryConsumer.accept(sd.entry);
        flaps.remove(sd.src);

        if (data.length > till)
            chunk(Arrays.copyOfRange(data, i, data.length), sd.src);
    }

    private static class SysStruct extends HashMap<String, String> {
        String name, tmp;

        void put(final String value) {
            put(name + "@@" + tmp, value);
        }
    }

    enum L2L {
        LEVEL_EMERGENCY(LogLevel.PANIC), LEVEL_ALERT(LogLevel.PANIC), LEVEL_CRITICAL(LogLevel.SEVERE), LEVEL_ERROR(LogLevel.ERROR), LEVEL_WARN(LogLevel.WARN), LEVEL_NOTICE(LogLevel.LOG),
        LEVEL_INFO(LogLevel.INFO), LEVEL_DEBUG(LogLevel.DEBUG);

        public final LogLevel ldl;

        L2L(final LogLevel ldl) {this.ldl = ldl;}
    }

    enum FACILITY {
        KERNEL, USER, MAIL, DAEMON, AUTH, SYSLOG, PRINT, NEWS, UUCP, CRON, AUTHPRIV, FTP, NTP, JOURNAL_AUDIT, JOURNAL_WARN, CRON_DAEMON, LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4,
        LOCAL5, LOCAL6, LOCAL7
    }

    private static class StreamData {
        public byte[] data;
        public int priority = -1;
        public Boolean bsd;
        public int version;
        public List<SysStruct> structs;
        public DataAddress src;
        private LogEntry entry;

        @Override
        public String toString() {
            return "StreamData{" +
                    (data != null ? "data=" + new String(data) : "") +
                    ", priority=" + priority +
                    ", bsd=" + bsd +
                    ", version=" + version +
                    ", structs=" + structs +
                    ", entry=" + entry +
                    '}';
        }
    }
}
