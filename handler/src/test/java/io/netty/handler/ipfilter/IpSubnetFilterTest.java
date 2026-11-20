/*
 * Copyright 2014 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.ipfilter;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.internal.SocketUtils;
import org.junit.Assert;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

public class IpSubnetFilterTest {

    @Test
    public void testIpv4DefaultRoute() {
        IpSubnetFilterRule rule = new IpSubnetFilterRule("0.0.0.0", 0, IpFilterRuleType.ACCEPT);
        Assert.assertTrue(rule.matches(newSockAddress("91.114.240.43")));
        Assert.assertTrue(rule.matches(newSockAddress("10.0.0.3")));
        Assert.assertTrue(rule.matches(newSockAddress("192.168.93.2")));
    }

    @Test
    public void testIpv4SubnetMaskCorrectlyHandlesIpv6() {
        IpSubnetFilterRule rule = new IpSubnetFilterRule("0.0.0.0", 0, IpFilterRuleType.ACCEPT);
        Assert.assertFalse(rule.matches(newSockAddress("2001:db8:abcd:0000::1")));
    }

    @Test
    public void testIpv6SubnetMaskCorrectlyHandlesIpv4() {
        IpSubnetFilterRule rule = new IpSubnetFilterRule("::", 0, IpFilterRuleType.ACCEPT);
        Assert.assertFalse(rule.matches(newSockAddress("91.114.240.43")));
    }

    @Test
    public void testIpv6DefaultRouteMatchesHighBitAddresses() {
        // ::/0 must match the entire IPv6 space, including addresses whose first
        // octet has the high bit set (unsigned). Using signed BigInteger(byte[])
        // incorrectly excludes these and breaks deny-all REJECT ::/0 ACLs.
        IpSubnetFilterRule acceptAll = new IpSubnetFilterRule("::", 0, IpFilterRuleType.ACCEPT);
        Assert.assertTrue(acceptAll.matches(newSockAddress("::1")));
        Assert.assertTrue(acceptAll.matches(newSockAddress("2001:db8::1")));
        Assert.assertTrue(acceptAll.matches(newSockAddress("fc00::1")));
        Assert.assertTrue(acceptAll.matches(newSockAddress("fd12:3456::1")));
        Assert.assertTrue(acceptAll.matches(newSockAddress("fe80::1")));
        Assert.assertTrue(acceptAll.matches(newSockAddress("ff02::1")));
        Assert.assertTrue(acceptAll.matches(newSockAddress("8000::1")));

        IpSubnetFilterRule rejectAll = new IpSubnetFilterRule("::", 0, IpFilterRuleType.REJECT);
        Assert.assertTrue(rejectAll.matches(newSockAddress("fe80::1")));
        Assert.assertTrue(rejectAll.matches(newSockAddress("fc00::1")));
    }

    @Test
    public void testRuleBasedIpFilterDenyAllIpv6DoesNotBypassHighBitSources() throws Exception {
        // ALLOWLIST pattern: accept a global unicast range, then REJECT ::/0.
        // High-bit sources must hit the REJECT catch-all, not fall through to
        // RuleBasedIpFilter's default-accept.
        RuleBasedIpFilter filter = new RuleBasedIpFilter(
                new IpSubnetFilterRule("2000::", 3, IpFilterRuleType.ACCEPT),
                new IpSubnetFilterRule("::", 0, IpFilterRuleType.REJECT));

        EmbeddedChannel allowed = newEmbeddedInetChannel("2001:db8::1", filter);
        Assert.assertTrue(allowed.isActive());

        EmbeddedChannel ulaDenied = newEmbeddedInetChannel("fd00::1", filter);
        Assert.assertFalse(ulaDenied.isActive());

        EmbeddedChannel linkLocalDenied = newEmbeddedInetChannel("fe80::1", filter);
        Assert.assertFalse(linkLocalDenied.isActive());
    }

    @Test
    public void testIp4SubnetFilterRule() throws Exception {
        IpSubnetFilterRule rule = new IpSubnetFilterRule("192.168.56.1", 24, IpFilterRuleType.ACCEPT);
        for (int i = 0; i <= 255; i++) {
            Assert.assertTrue(rule.matches(newSockAddress(String.format("192.168.56.%d", i))));
        }
        Assert.assertFalse(rule.matches(newSockAddress("192.168.57.1")));

        rule = new IpSubnetFilterRule("91.114.240.1", 23, IpFilterRuleType.ACCEPT);
        Assert.assertTrue(rule.matches(newSockAddress("91.114.240.43")));
        Assert.assertTrue(rule.matches(newSockAddress("91.114.240.255")));
        Assert.assertTrue(rule.matches(newSockAddress("91.114.241.193")));
        Assert.assertTrue(rule.matches(newSockAddress("91.114.241.254")));
        Assert.assertFalse(rule.matches(newSockAddress("91.115.241.2")));
    }

    @Test
    public void testIp6SubnetFilterRule() {
        IpSubnetFilterRule rule;

        rule = new IpSubnetFilterRule("2001:db8:abcd:0000::", 52, IpFilterRuleType.ACCEPT);
        Assert.assertTrue(rule.matches(newSockAddress("2001:db8:abcd:0000::1")));
        Assert.assertTrue(rule.matches(newSockAddress("2001:db8:abcd:0fff:ffff:ffff:ffff:ffff")));
        Assert.assertFalse(rule.matches(newSockAddress("2001:db8:abcd:1000::")));
    }

    @Test
    public void testIpFilterRuleHandler() throws Exception {
        IpFilterRule filter0 = new IpFilterRule() {
            @Override
            public boolean matches(InetSocketAddress remoteAddress) {
                return "192.168.57.1".equals(remoteAddress.getHostName());
            }

            @Override
            public IpFilterRuleType ruleType() {
                return IpFilterRuleType.REJECT;
            }
        };

        RuleBasedIpFilter denyHandler = new RuleBasedIpFilter(filter0) {
            private final byte[] message = {1, 2, 3, 4, 5, 6, 7};

            @Override
            protected ChannelFuture channelRejected(ChannelHandlerContext ctx, InetSocketAddress remoteAddress) {
                Assert.assertTrue(ctx.channel().isActive());
                Assert.assertTrue(ctx.channel().isWritable());
                Assert.assertEquals("192.168.57.1", remoteAddress.getHostName());

                return ctx.writeAndFlush(Unpooled.wrappedBuffer(message));
            }
        };
        EmbeddedChannel chDeny = newEmbeddedInetChannel("192.168.57.1", denyHandler);
        ByteBuf out = chDeny.readOutbound();
        Assert.assertEquals(7, out.readableBytes());
        for (byte i = 1; i <= 7; i++) {
            Assert.assertEquals(i, out.readByte());
        }
        Assert.assertFalse(chDeny.isActive());
        Assert.assertFalse(chDeny.isOpen());

        RuleBasedIpFilter allowHandler = new RuleBasedIpFilter(filter0) {
            @Override
            protected ChannelFuture channelRejected(ChannelHandlerContext ctx, InetSocketAddress remoteAddress) {
                Assert.fail();
                return null;
            }
        };
        EmbeddedChannel chAllow = newEmbeddedInetChannel("192.168.57.2", allowHandler);
        Assert.assertTrue(chAllow.isActive());
        Assert.assertTrue(chAllow.isOpen());
    }

    @Test
    public void testUniqueIpFilterHandler() {
        UniqueIpFilter handler = new UniqueIpFilter();

        EmbeddedChannel ch1 = newEmbeddedInetChannel("91.92.93.1", handler);
        Assert.assertTrue(ch1.isActive());
        EmbeddedChannel ch2 = newEmbeddedInetChannel("91.92.93.2", handler);
        Assert.assertTrue(ch2.isActive());
        EmbeddedChannel ch3 = newEmbeddedInetChannel("91.92.93.1", handler);
        Assert.assertFalse(ch3.isActive());

        // false means that no data is left to read/write
        Assert.assertFalse(ch1.finish());

        EmbeddedChannel ch4 = newEmbeddedInetChannel("91.92.93.1", handler);
        Assert.assertTrue(ch4.isActive());
    }

    @Test
    public void testUniqueIpFilterConcurrentSameIpAcceptedOnce() throws Exception {
        // Multi-threaded accept of the same IP must honor one-IP-one-Channel. The old
        // contains-then-add path ignored ConcurrentSet.add's putIfAbsent result so a
        // losing racer still returned true.
        final UniqueIpFilter handler = new UniqueIpFilter();
        final int threads = 32;
        final java.util.concurrent.atomic.AtomicInteger accepted =
                new java.util.concurrent.atomic.AtomicInteger();
        final java.util.concurrent.CountDownLatch start =
                new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.CountDownLatch done =
                new java.util.concurrent.CountDownLatch(threads);
        final java.util.concurrent.ExecutorService es =
                java.util.concurrent.Executors.newFixedThreadPool(threads);
        final java.util.List<EmbeddedChannel> channels =
                java.util.Collections.synchronizedList(new java.util.ArrayList<EmbeddedChannel>());
        try {
            for (int i = 0; i < threads; i++) {
                es.execute(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            start.await();
                            EmbeddedChannel ch = newEmbeddedInetChannel("10.20.30.40", handler);
                            channels.add(ch);
                            if (ch.isActive()) {
                                accepted.incrementAndGet();
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            done.countDown();
                        }
                    }
                });
            }
            start.countDown();
            Assert.assertTrue(done.await(30, java.util.concurrent.TimeUnit.SECONDS));
            Assert.assertEquals("only one concurrent connect from the same IP may be accepted",
                    1, accepted.get());
        } finally {
            es.shutdownNow();
            for (EmbeddedChannel ch : channels) {
                ch.finishAndReleaseAll();
            }
        }
    }

    @Test
    public void testIpv4MappedAddressDoesNotMatchIpv4OnlyRule() throws Exception {
        // After the unsigned BigInteger fix, IPv4-mapped Inet6Address still does not match
        // Ip4SubnetFilterRule (family split). Native transport normalizes ::ffff: peers to
        // Inet4Address on accept, so dual-stack TCP peers are not an ACL bypass here; this
        // test documents the intentional family mismatch for forced Inet6 mapped forms.
        IpSubnetFilterRule rejectV4 = new IpSubnetFilterRule("10.0.0.0", 8, IpFilterRuleType.REJECT);
        byte[] mapped = new byte[16];
        mapped[10] = (byte) 0xff;
        mapped[11] = (byte) 0xff;
        mapped[12] = 10;
        mapped[13] = 1;
        mapped[14] = 2;
        mapped[15] = 3;
        java.net.Inet6Address mappedAddr =
                java.net.Inet6Address.getByAddress(null, mapped, -1);
        Assert.assertFalse(rejectV4.matches(new InetSocketAddress(mappedAddr, 1234)));
        Assert.assertTrue(rejectV4.matches(newSockAddress("10.1.2.3")));
    }

    private static EmbeddedChannel newEmbeddedInetChannel(final String ipAddress, ChannelHandler... handlers) {
        return new EmbeddedChannel(handlers) {
            @Override
            protected SocketAddress remoteAddress0() {
                return isActive()? SocketUtils.socketAddress(ipAddress, 5421) : null;
            }
        };
    }

    private static InetSocketAddress newSockAddress(String ipAddress) {
        return SocketUtils.socketAddress(ipAddress, 1234);
    }
}
