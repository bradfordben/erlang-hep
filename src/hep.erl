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

-module(hep).

-include("hep.hrl").

-export([encode/1]).
-export([decode/1]).

-export([ new/0
        , version/1, version/2
        , protocol_family/1, protocol_family/2
        , protocol/1, protocol/2
        , src_ip/1, src_ip/2
        , dst_ip/1, dst_ip/2
        , src_port/1, src_port/2
        , dst_port/1, dst_port/2
        , timestamp/1, timestamp/2
        , payload_type/1, payload_type/2
        , node_id/1, node_id/2
        , keep_alive_timer/1, keep_alive_timer/2
        , authenticate_key/1, authenticate_key/2
        , payload/1, payload/2
        , payload_compressed/1, payload_compressed/2
        , internal_correlation_id/1, internal_correlation_id/2
        , vlan_id/1, vlan_id/2
        , capture_agent_string_id/1, capture_agent_string_id/2
        , src_mac/1, src_mac/2
        , dst_mac/1, dst_mac/2
        , ethernet_type/1, ethernet_type/2
        , tcp_flag/1, tcp_flag/2
        , ip_tos/1, ip_tos/2
        , mos_value/1, mos_value/2
        , r_factor/1, r_factor/2
        , geo_location/1, geo_location/2
        , jitter/1, jitter/2
        , transaction_type/1, transaction_type/2
        , payload_json_keys/1, payload_json_keys/2
        , tags_values/1, tags_values/2
        , type_of_tag/1, type_of_tag/2
        , event_type/1, event_type/2
        , group_id/1, group_id/2
        , vendor/1, vendor/2
        ]).

-export_type([ t/0
             , version/0
             , vendor/0
             , uint8/0
             , uint16/0
             , uint32/0
             , uint64/0 ]).

-opaque t () :: #hep{}.

-type version () :: 'hep_v1' | 'hep_v2' | 'hep_v3'.
-type vendor () :: 'unknown'
                 | 'freeswitch'
                 | 'kamailio'
                 | 'opensips'
                 | 'asterisk'
                 | 'homer'
                 | 'sipxecs'.
-type protocol_family () :: 'ipv4' | 'ipv6'.
-type payload_type () :: 'reserved'
                       | 'sip'
                       | 'xmpp'
                       | 'sdp'
                       | 'rtp'
                       | 'rtcp'
                       | 'mgcp'
                       | 'megaco'
                       | 'm2ua'
                       | 'm3ua'
                       | 'iax'
                       | 'h322'
                       | 'h321'.

-type uint8 () :: 0..255.
-type uint16 () :: 0..65535.
-type uint32 () :: 0..4294967295.
-type uint64 () :: 0..18446744073709599999.

%% API

-spec encode (t()) -> {ok, binary()} | {error, _}.
encode (#hep{version = Version} = Hep)
  when Version == 'hep_v1'; Version == 'hep_v2'; Version == 'hep_v3' ->
    Version:encode(Hep);
encode (Hep) ->
    {error, {invalid_hep, Hep}}.


-spec decode (binary()) -> {ok, t()} | {error, _}.
decode (Packet = <<?HEP_V1_ID, _Rest/binary>>) ->
    hep_v1:decode(Packet);
decode (Packet = <<?HEP_V2_ID, _Rest/binary>>) ->
    hep_v2:decode(Packet);
decode (Packet = <<?HEP_V3_ID, _Rest/binary>>) ->
    hep_v3:decode(Packet);
decode (Packet = <<_/binary>>) ->
    {error, invalid_packet, Packet}.


-spec version (t()) -> version().
version (#hep{version = Version}) ->
    Version;
version (Hep) ->
    {error, {invalid_packet, Hep}}.


%% Note: you can't have a dot inside a macro definition!
-define(getter(Field),Field(#hep{Field = Val}) -> Val).
-define(setter(Field), Field(Val, Hep) -> Hep#hep{Field = Val}).

-spec payload(hep:t()) -> binary().
-spec timestamp(hep:t()) -> erlang:timestamp().

-spec src_ip(hep:t()) -> inet:ip_address().
-spec dst_ip(hep:t()) -> inet:ip_address().

-spec src_port(hep:t()) -> inet:port_number().
-spec dst_port(hep:t()) -> inet:port_number().

new () -> #hep{}.
?setter(version).
?getter(protocol_family).
?setter(protocol_family).
?getter(protocol).
?setter(protocol).
?getter(src_ip).
?setter(src_ip).
?getter(dst_ip).
?setter(dst_ip).
?getter(src_port).
?setter(src_port).
?getter(dst_port).
?setter(dst_port).
?getter(timestamp).
?setter(timestamp).
?getter(payload_type).
?setter(payload_type).
?getter(node_id).
?setter(node_id).
?getter(keep_alive_timer).
?setter(keep_alive_timer).
?getter(authenticate_key).
?setter(authenticate_key).
?getter(payload).
?setter(payload).
?getter(payload_compressed).
?setter(payload_compressed).
?getter(internal_correlation_id).
?setter(internal_correlation_id).
?getter(vlan_id).
?setter(vlan_id).
?getter(capture_agent_string_id).
?setter(capture_agent_string_id).
?getter(src_mac).
?setter(src_mac).
?getter(dst_mac).
?setter(dst_mac).
?getter(ethernet_type).
?setter(ethernet_type).
?getter(tcp_flag).
?setter(tcp_flag).
?getter(ip_tos).
?setter(ip_tos).
?getter(mos_value).
?setter(mos_value).
?getter(r_factor).
?setter(r_factor).
?getter(geo_location).
?setter(geo_location).
?getter(jitter).
?setter(jitter).
?getter(transaction_type).
?setter(transaction_type).
?getter(payload_json_keys).
?setter(payload_json_keys).
?getter(tags_values).
?setter(tags_values).
?getter(type_of_tag).
?setter(type_of_tag).
?getter(event_type).
?setter(event_type).
?getter(group_id).
?setter(group_id).
?getter(vendor).
?setter(vendor).

%% Internals

%% End of Module.
