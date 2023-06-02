package org.logdoc.sinks;

import com.typesafe.config.Config;
import org.logdoc.sdk.ConnectionType;
import org.logdoc.sdk.SinkPlugin;
import org.logdoc.structs.DataAddress;
import org.logdoc.structs.LogEntry;
import org.logdoc.structs.enums.Proto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;

import static org.logdoc.LogDocConstants.Fields.Ip;
import static org.logdoc.LogDocConstants.header;
import static org.logdoc.helpers.BinFlows.asInt;
import static org.logdoc.helpers.Texts.isEmpty;

/**
 * Logdoc native protocol handler (UDP)
 */
public class LogdocUdpHandler implements SinkPlugin {
    private static final Logger logger = LoggerFactory.getLogger(LogdocUdpHandler.class);
    private static final long expired = 1000L * 60L * 3L;
    private static final Set<ConnectionType> ct = Collections.singleton(new ConnectionType());

    static {
        ct.iterator().next().proto = Proto.UDP;
        ct.iterator().next().name = "Logdoc-Logback-Udp-Handler";
    }

    private final ConcurrentMap<TimedId, AllData> flaps;
    private Consumer<LogEntry> entryConsumer;

    public LogdocUdpHandler() {
        flaps = new ConcurrentHashMap<>(1);
    }

    @Override
    public void configure(final Config config, final Consumer<LogEntry> entryConsumer) {
        this.entryConsumer = entryConsumer;
    }

    @Override
    public Set<ConnectionType> sinkTypes() {
        return ct;
    }

    @Override
    public byte[] chunk(final byte[] data, final DataAddress source) {
        if (data == null || data.length < 20 || data[0] != header[0] || data[1] != header[1])
            return null;

        final short cycles = data[2];

        if (cycles < 2) {
            doEntry(new AllData(data, source.ip(), source.host()));
            return null;
        }

        final byte[] token = Arrays.copyOfRange(data, 4, 20);

        TimedId id = null;
        for (TimedId tid : flaps.keySet())
            if (Arrays.equals(token, tid.token)) {
                id = tid;
                break;
            }

        if (id == null) {
            id = new TimedId(token, source);
            flaps.put(id, new AllData(cycles, source.ip(), source.host()));
        }

        final short cycle = data[3];
        flaps.get(id).set(cycle, data);

        if (flaps.get(id).isComplete()) {
            doEntry(flaps.remove(id));
            return null;
        }

        if (!flaps.isEmpty() && flaps.size() % 2 == 0)
            doFlushExpired();

        return null;
    }

    private void doEntry(final AllData allData) {
        try {
            final LogEntry entry = new LogEntry();
            allData.inflate();

            String fieldName, value;
            do {
                fieldName = allData.peekFieldname();

                if (fieldName != null) {
                    value = allData.peekValue();

                    if (isEmpty(value))
                        continue;

                    entry.field(fieldName, value);
                }
            } while (fieldName != null);

            entry.field(Ip, allData.ip);
            entry.field("host", allData.host);
            entryConsumer.accept(entry);
        } catch (final Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    private void doFlushExpired() {
        if (flaps.isEmpty())
            return;

        final long now = System.currentTimeMillis();
        final SortedSet<TimedId> ids = new TreeSet<>(flaps.keySet());

        for (TimedId id : ids)
            if (now - id.time >= expired)
                flaps.remove(id);
    }


    private static final class TimedId implements Comparable<TimedId> {
        private final long time;
        private final byte[] token;
        private final DataAddress address;

        public TimedId(final byte[] token, final DataAddress address) {
            this.token = token;
            this.address = address;
            time = System.currentTimeMillis();
        }

        @Override
        public int compareTo(final TimedId o) {
            return Long.compare(time, o.time);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            final TimedId timedId = (TimedId) o;
            return Arrays.equals(token, timedId.token) && address.equals(timedId.address);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(address);
            result = 31 * result + Arrays.hashCode(token);
            return result;
        }
    }

    private static final class AllData extends ArrayList<byte[]> {
        private int list = 0, i = 20, size;
        private byte b;
        private final ByteArrayOutputStream os = new ByteArrayOutputStream(128);
        private final String ip, host;

        public AllData(final int size, final String ip, final String host) {
            super(size);
            for (int i = 0; i < size; i++)
                add(null);

            this.ip = ip;
            this.host = host;
        }

        public AllData(final byte[] data, final String ip, final String host) {
            this.host = host;
            add(data);
            this.ip = ip;
        }

        public String peekFieldname() {
            os.reset();
            b = next();
            while (b != '\n' && b != '=') {
                os.write(b);
                b = next();
            }

            if (os.size() == 0)
                return null;

            if (b == '\n')
                size = asInt(new byte[]{next(), next(), next(), next()});
            else
                size = -1;

            return new String(os.toByteArray(), StandardCharsets.UTF_8);
        }

        public String peekValue() {
            os.reset();

            if (size > 0) {
                for (int j = 0; j < size; j++)
                    os.write(next());
            } else {
                b = next();

                while (b != '\n') {
                    os.write(b);
                    b = next();
                }
            }

            size = -1;
            return new String(os.toByteArray(), StandardCharsets.UTF_8);
        }

        private byte next() {
            if (i == get(list).length) {
                list++;
                i = 20;
            }

            return get(list)[i++];
        }

        public boolean isComplete() {
            for (final byte[] bb : this)
                if (bb == null)
                    return false;

            return true;
        }

        public void inflate() {
            for (int i = 0; i < size(); i++)
                if (get(i) == null)
                    remove(i--);
        }
    }
}
