%% Copyright (c) 2013, Matthias Endler <matthias.endler@pantech.at>
%%
%% Permission to use, copy, modify, and distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-ifndef(HEP_HRL).

-record(hep, { version :: hep:version()

             , protocol_family :: hep:protocol_family()
             , protocol :: hep:uint8()
             , src_ip :: inet:ip_address()
             , src_port :: inet:port_number()
             , dst_ip :: inet:ip_address()
             , dst_port :: inet:port_number()
             , timestamp :: erlang:timestamp()
             , node_id :: hep:uint16() | hep:uint32() | undefined  %% undefined in: v1
             , payload_type :: hep:payload_type()
             , payload :: binary()
             , vendor :: hep:vendor() | undefined  %% undefined in: v1, v2
             , keep_alive_timer :: hep:uint16()
             , authenticate_key :: binary()
             , payload_compressed :: binary()
             , internal_correlation_id :: binary()
             , vlan_id :: hep:uint16()
             , capture_agent_string_id :: binary()
             , src_mac :: hep:uint64()
             , dst_mac :: hep:uint64()
             , ethernet_type :: hep:uint16()
             , tcp_flag :: hep:uint8()
             , ip_tos :: hep:uint8()
             , mos_value :: hep:uint16()
             , r_factor :: hep:uint16()
             , geo_location :: binary()
             , jitter :: hep:uint32()
             , transaction_type :: binary()
             , payload_json_keys :: binary()
             , tags_values :: binary()
             , type_of_tag :: hep:uint16()
             , event_type :: hep:uint16()
             , group_id :: binary()
             }).

%% HEP Version IDs
-define(HEP_V1_ID, 1:8).
-define(HEP_V2_ID, 2:8).
-define(HEP_V3_ID, "HEP3").

%% Protocol Families
-define(FAMILY_IPV4, 16#02).
-define(FAMILY_IPV6, 16#0a).

%% Binary patterns
-define(vendor(Val), (Val):16).
-define(type(Val),   (Val):16).
-define(protocol_family(Val), (Val):8).
-define(protocol(Val), (Val):8).
-define(port(Val),   (Val):16).
-define(timestamp(Val), (Val):32).
-define(payload_type(Val), (Val):8).
-define(ipv4(I1, I2, I3, I4),
        (I1):8, (I2):8, (I3):8, (I4):8).
-define(ipv6(I1, I2, I3, I4, I5, I6, I7, I8),
        (I1):16, (I2):16, (I3):16, (I4):16, (I5):16, (I6):16, (I7):16, (I8):16).

%% Capture Protocol Types (0xb) (also called Payload Type)
-define(PROTOCOL_RESERVED, 16#00).
-define(PROTOCOL_SIP,      16#01).
-define(PROTOCOL_XMPP,     16#02).
-define(PROTOCOL_SDP,      16#03).
-define(PROTOCOL_RTP,      16#04).
-define(PROTOCOL_RTCP,     16#05).
-define(PROTOCOL_MGCP,     16#06).
-define(PROTOCOL_MEGACO,   16#07).
-define(PROTOCOL_M2UA,     16#08).
-define(PROTOCOL_M3UA,     16#09).
-define(PROTOCOL_IAX,      16#0a).
-define(PROTOCOL_H322,     16#0b).
-define(PROTOCOL_H321,     16#0c).
-define(PROTOCOL_M2PA,     16#0d).
-define(PROTOCOL_MOS_FULL, 16#22).
-define(PROTOCOL_MOS_SHORT,16#23).
-define(PROTOCOL_SIP_JSON, 16#32).
-define(PROTOCOL_DNS_JSON, 16#35).
-define(PROTOCOL_M3UA_JSON,16#36).
-define(PROTOCOL_RTSP,     16#37).
-define(PROTOCOL_DIAMETER, 16#38).
-define(PROTOCOL_GSM_MAP,  16#39).
-define(PROTOCOL_RTCP_PION,16#3a).
-define(PROTOCOL_CDR,      16#3c).
-define(PROTOCOL_LOG,      16#64).

-define(HEP_HRL, true).
-endif.
