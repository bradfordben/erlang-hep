%% -*- coding: utf-8 -*-
-module(hep_v3).

-include("hep.hrl").

-export([encode/1]).
-export([decode/1]).

%% Generic Chunk Types
-define(IP_PROTOCOL_FAMILY,          16#0001).
-define(IP_PROTOCOL_ID,              16#0002).
-define(IPV4_SOURCE_ADDRESS,         16#0003).
-define(IPV4_DESTINATION_ADDRESS,    16#0004).
-define(IPV6_SOURCE_ADDRESS,         16#0005).
-define(IPV6_DESTINATION_ADDRESS,    16#0006).
-define(PROTOCOL_SOURCE_PORT,        16#0007).
-define(PROTOCOL_DESTINATION_PORT,   16#0008).
-define(TIMESTAMP_IN_SECONDS,        16#0009).
-define(TIMESTAMP_MS_OFFSET,         16#000a).
-define(PROTOCOL_TYPE,               16#000b).
-define(CAPTURE_AGENT_ID,            16#000c).
-define(KEEP_ALIVE_TIMER,            16#000d).
-define(AUTHENTICATE_KEY,            16#000e).
-define(CAPTURED_PACKET_PAYLOAD,     16#000f).
-define(CAPTURED_COMPRESSED_PAYLOAD, 16#0010).
-define(INTERNAL_CORRELATION_ID,     16#0011).
-define(VLAN_ID,                     16#0012).
-define(CAPTURE_AGENT_STRING_ID,     16#0013).
-define(SOURCE_MAC,                  16#0014).
-define(DESTINATION_MAC,             16#0015).
-define(ETHERNET_TYPE,               16#0016).
-define(TCP_FLAG,                    16#0017).
-define(IP_TOS,                      16#0018).
-define(MOS_VALUE,                   16#0020).
-define(R_FACTOR,                    16#0021).
-define(GEO_LOCATION,                16#0022).
-define(JITTER,                      16#0023).
-define(TRANSACTION_TYPE,            16#0024).
-define(PAYLOAD_JSON_KEYS,           16#0025).
-define(TAGS_VALUES,                 16#0026).
-define(TYPE_OF_TAGS,                16#0027).
-define(EVENT_TYPE,                  16#0028).
-define(GROUP_ID,                    16#0029).

%% Chunk Vendor ID
-define(VENDOR_UNKNOWN,       16#0000).
-define(VENDOR_FREESWITCH,    16#0001).
-define(VENDOR_KAMALIO_SER,   16#0002).
-define(VENDOR_OPENSIPS,      16#0003).
-define(VENDOR_ASTERISK,      16#0004).
-define(VENDOR_HOMER_PROJECT, 16#0005).
-define(VENDOR_SIPXECS,       16#0006).

%% Padding out values
-define(node_id(Val), (Val):32).
-define(keep_alive_timer(Val), (Val):16).
-define(vlan_id(Val), (Val):16).
-define(ethernet_type(Val), (Val):16).
-define(mos_value(Val), (Val):16).
-define(r_factor(Val), (Val):16).
-define(jitter(Val), (Val):32).
-define(type_of_tag(Val), (Val):16).
-define(event_type(Val), (Val):16).
-define(length(Val), (Val):16).

%% API

-spec encode (hep:t()) -> {ok, binary()} | {error, _}.

encode (#hep{version = ?MODULE} = Hep) ->
    Payload = pack_chunks(Hep),
    case byte_size(Payload) + length(?HEP_V3_ID) + 2 of
        TotalLength when TotalLength > 65535 ->
            {error, {packet_too_large}};
        TotalLength ->
            {ok, <<?HEP_V3_ID, ?length(TotalLength), Payload/binary>>}
    end;
encode (Hep) ->
    {error, {invalid_hep, Hep}}.



-spec decode (binary()) -> {ok, hep:t()} | {error, _}.

decode (<<?HEP_V3_ID, ?length(TotalLength), Rest/binary>>)
  when TotalLength >= 6 ->
    Length = TotalLength - length(?HEP_V3_ID) - 2,
    <<Payload:Length/binary>> = Rest,
    case chunks_from_payload(Payload, #hep{version = ?MODULE}) of
        {error,_}=Error -> Error;
        Hep ->
            case {Hep#hep.src_ip, Hep#hep.dst_ip} of
                {{_,_,_,_}, {_,_,_,_}} ->
                    {ok, Hep#hep{protocol_family = 'ipv4'}};
                {{_,_,_,_,_,_,_,_}, {_,_,_,_,_,_,_,_}} ->
                    {ok, Hep#hep{protocol_family = 'ipv6'}};
                {SrcIP, DstIP} ->
                    {error, {ips_of_unmatching_protocols,SrcIP,DstIP}}
            end
    end;
decode (<<Packet/binary>>) ->
    {error, {invalid_packet, Packet}}.

%% Internals

%% @private
-spec vendor (hep:uint16() | atom()) -> atom() | hep:uint16() | {error, _}.
vendor (?VENDOR_UNKNOWN) -> 'unknown';
vendor (?VENDOR_FREESWITCH) -> 'freeswitch';
vendor (?VENDOR_KAMALIO_SER) -> 'kamailio';
vendor (?VENDOR_OPENSIPS) -> 'opensips';
vendor (?VENDOR_ASTERISK) -> 'asterisk';
vendor (?VENDOR_HOMER_PROJECT) -> 'homer';
vendor (?VENDOR_SIPXECS) -> 'sipxecs';
vendor ('unknown') -> ?VENDOR_UNKNOWN;
vendor ('freeswitch') -> ?VENDOR_FREESWITCH;
vendor ('kamailio') -> ?VENDOR_KAMALIO_SER;
vendor ('opensips') -> ?VENDOR_OPENSIPS;
vendor ('asterisk') -> ?VENDOR_ASTERISK;
vendor ('homer') -> ?VENDOR_HOMER_PROJECT;
vendor ('sipxecs') -> ?VENDOR_SIPXECS;
vendor (Vendor) ->
    {error, {invalid_vendor, Vendor}}.

%% @private
chunks_from_payload (<<>>, Hep) -> Hep;
chunks_from_payload (Payload, PrevHep) ->
    case chunk_from_payload(PrevHep, Payload) of
        {{error,_}=Error, _Rest} -> Error;
        {NewHep, Continuation} -> chunks_from_payload(Continuation, NewHep)
    end.

%% @private
chunk_from_payload (Hep, <<?vendor(Vendor), ?type(Type), ?length(Length), Rest/binary>>) ->
    DataLength = Length -2 -2 -2,
    <<Data:DataLength/binary, Continuation/binary>> = Rest,
    NewHep = case vendor(Vendor) of
                 {error, _}=Error -> Error;
                 VendorId -> set_field(Data, Type, Hep#hep{vendor = VendorId})
             end,
    {NewHep, Continuation}.

%% @private
set_field (<<?protocol_family(Data)>>, ?IP_PROTOCOL_FAMILY, Hep) ->
    case hep_util:protocol_family(Data) of
        {error,_}=Error -> Error;
        ProtocolFamily -> Hep#hep{protocol_family = ProtocolFamily}
    end;
set_field (<<?protocol(Data)>>, ?IP_PROTOCOL_ID, Hep) ->
    Hep#hep{protocol = Data};
set_field (<<?ipv4(I1, I2, I3, I4)>>, ?IPV4_SOURCE_ADDRESS, Hep) ->
    Hep#hep{src_ip = {I1, I2, I3, I4}};
set_field (<<?ipv4(I1, I2, I3, I4)>>, ?IPV4_DESTINATION_ADDRESS, Hep) ->
    Hep#hep{dst_ip = {I1, I2, I3, I4}};
set_field (<<?ipv6(I1, I2, I3, I4, I5, I6, I7, I8)>>, ?IPV6_SOURCE_ADDRESS, Hep) ->
    Hep#hep{src_ip = {I1, I2, I3, I4, I5, I6, I7, I8}};
set_field (<<?ipv6(I1, I2, I3, I4, I5, I6, I7, I8)>>, ?IPV6_DESTINATION_ADDRESS, Hep) ->
    Hep#hep{dst_ip = {I1, I2, I3, I4, I5, I6, I7, I8}};
set_field (<<?port(Data)>>, ?PROTOCOL_SOURCE_PORT, Hep) ->
    Hep#hep{src_port = Data};
set_field (<<?port(Data)>>, ?PROTOCOL_DESTINATION_PORT, Hep) ->
    Hep#hep{dst_port = Data};
set_field (<<?timestamp(Secs)>>, ?TIMESTAMP_IN_SECONDS, Hep = #hep{timestamp = TS}) ->
    MegaSecs = Secs div 1000000,
    TSSecs   = Secs rem 1000000,
    case TS of
        {_, _, Micros} ->
            Hep#hep{timestamp = {MegaSecs, TSSecs, Micros}};
        undefined ->
            Hep#hep{timestamp = {MegaSecs, TSSecs, 0}}
    end;
set_field (<<?timestamp(MicroSecs)>>, ?TIMESTAMP_MS_OFFSET, Hep = #hep{timestamp = TS}) ->
    case TS of
        undefined ->
            Hep#hep{timestamp = {0, 0, MicroSecs}};
        {M, S, _} ->
            Hep#hep{timestamp = {M, S, MicroSecs}}
    end;
set_field (<<?payload_type(Data)>>, ?PROTOCOL_TYPE, Hep) ->
    case hep_util:payload_type(Data) of
        {error, _}=Error -> Error;
        Protocol -> Hep#hep{payload_type = Protocol}
    end;
set_field (<<?node_id(Data)>>, ?CAPTURE_AGENT_ID, Hep) ->
    Hep#hep{node_id = Data};
set_field (<<_Data:16>>, ?KEEP_ALIVE_TIMER, Hep) ->
    %% Hep#hep{keep_alive_timer = Data};
    Hep;
set_field (<<_Data:8>>, ?VLAN_ID, Hep) ->
    %% Hep#hep{vlan_id = Data}.
    Hep;
set_field (_Data, ?AUTHENTICATE_KEY, Hep) ->
    %% Hep#hep{authenticate_key = Data};
    Hep;
set_field (Data, ?CAPTURED_PACKET_PAYLOAD, Hep) ->
    Hep#hep{payload = Data};
set_field (Data, ?CAPTURED_COMPRESSED_PAYLOAD, Hep) ->
    Hep#hep{payload = Data};
set_field (_Data, ?INTERNAL_CORRELATION_ID, Hep) ->
    %% Hep#hep{internal_correlation_id = Data};
    Hep.


pack_chunks (Hep) ->
    Fields = [ protocol_family
             , protocol
             , src_ip
             , dst_ip
             , src_port
             , dst_port
             , timestamp
             , node_id
             , payload_type
             , keep_alive_timer
             , authenticate_key
             , payload
             , payload_compressed
             , internal_correlation_id
             , vlan_id
             , capture_agent_string_id
             , src_mac
             , dst_mac
             , ethernet_type
             , tcp_flag
             , ip_tos
             , mos_value
             , r_factor
             , geo_location
             , jitter
             , transaction_type
             , payload_json_keys
             , tags_values
             , type_of_tag
             , event_type
             , group_id
             ],
    << <<(make_chunk(Field, Hep))/binary>> || Field <- Fields >>.


make_chunk (protocol_family, #hep{protocol_family = Data}=Hep) ->
    do_make_chunk(Hep, ?IP_PROTOCOL_FAMILY, <<?protocol_family(hep_util:protocol_family(Data))>>);
make_chunk (protocol, #hep{protocol = Data}=Hep) ->
    do_make_chunk(Hep, ?IP_PROTOCOL_ID, <<?protocol(Data)>>);

make_chunk (src_ip, #hep{ protocol_family = 'ipv4'
                        , src_ip = {I1, I2, I3, I4}
                        }=Hep) ->
    do_make_chunk(Hep, ?IPV4_SOURCE_ADDRESS, <<?ipv4(I1, I2, I3, I4)>>);
make_chunk (src_ip, #hep{ protocol_family = 'ipv6'
                        , src_ip = {I1, I2, I3, I4, I5, I6, I7, I8}
                        }=Hep) ->
    do_make_chunk(Hep, ?IPV6_SOURCE_ADDRESS, <<?ipv6(I1, I2, I3, I4, I5, I6, I7, I8)>>);

make_chunk (dst_ip, #hep{ protocol_family = 'ipv4'
                        , dst_ip = {I1, I2, I3, I4}
                        }=Hep) ->
    do_make_chunk(Hep, ?IPV4_DESTINATION_ADDRESS, <<?ipv4(I1, I2, I3, I4)>>);
make_chunk (dst_ip, #hep{ protocol_family = 'ipv6'
                        , dst_ip = {I1, I2, I3, I4, I5, I6, I7, I8}
                        }=Hep) ->
    do_make_chunk(Hep, ?IPV6_DESTINATION_ADDRESS, <<?ipv6(I1, I2, I3, I4, I5, I6, I7, I8)>>);

make_chunk (src_port, #hep{src_port = Data}=Hep) ->
    do_make_chunk(Hep, ?PROTOCOL_SOURCE_PORT, <<?port(Data)>>);
make_chunk (dst_port, #hep{dst_port = Data}=Hep) ->
    do_make_chunk(Hep, ?PROTOCOL_DESTINATION_PORT, <<?port(Data)>>);

make_chunk (timestamp, #hep{timestamp = Timestamp}=Hep) ->
    Seconds = hep_util:timestamp_secs(Timestamp),
    Micros  = hep_util:timestamp_microsecs(Timestamp),
    Chunk1 = do_make_chunk(Hep, ?TIMESTAMP_IN_SECONDS, <<?timestamp(Seconds)>>),
    Chunk2 = do_make_chunk(Hep, ?TIMESTAMP_MS_OFFSET, <<?timestamp(Micros)>>),
    <<Chunk1/binary, Chunk2/binary>>;

make_chunk (node_id, #hep{node_id = Data}=Hep) ->
    do_make_chunk(Hep, ?CAPTURE_AGENT_ID, <<?node_id(Data)>>);

make_chunk (payload_type, #hep{payload_type = Data}=Hep) ->
    do_make_chunk(Hep, ?PROTOCOL_TYPE, <<?payload_type(hep_util:payload_type(Data))>>);

make_chunk (keep_alive_timer, #hep{keep_alive_timer = undefined}=_Hep) ->
    <<>>;
make_chunk (keep_alive_timer, #hep{keep_alive_timer = Value}=Hep) ->
    do_make_chunk(Hep, ?KEEP_ALIVE_TIMER, <<?keep_alive_timer(Value)>>);

make_chunk (authenticate_key, #hep{authenticate_key = undefined}=_Hep) ->
    <<>>;
make_chunk (authenticate_key, #hep{authenticate_key = Value}=Hep) ->
    do_make_chunk(Hep, ?AUTHENTICATE_KEY, Value);

make_chunk (payload, #hep{payload = undefined}=_Hep) ->
    <<>>;
make_chunk (payload, #hep{payload = Payload}=Hep) ->
    do_make_chunk(Hep, ?CAPTURED_PACKET_PAYLOAD, Payload);

make_chunk (payload_compressed, #hep{payload_compressed = undefined}=_Hep) ->
    <<>>;
make_chunk (payload_compressed, #hep{payload_compressed = Payload}=Hep) ->
    do_make_chunk(Hep, ?CAPTURED_COMPRESSED_PAYLOAD, Payload);

make_chunk (internal_correlation_id, #hep{internal_correlation_id = undefined}=_Hep) ->
    <<>>;
make_chunk (internal_correlation_id, #hep{internal_correlation_id = Payload}=Hep) ->
    do_make_chunk(Hep, ?INTERNAL_CORRELATION_ID, Payload);

make_chunk (vlan_id, #hep{vlan_id = undefined}=_Hep) ->
    <<>>;
make_chunk (vlan_id, #hep{vlan_id = VlanId}=Hep) ->
    do_make_chunk(Hep, ?VLAN_ID, <<?vlan_id(VlanId)>>);

make_chunk (capture_agent_string_id, #hep{capture_agent_string_id = undefined}=_Hep) ->
    <<>>;
make_chunk (capture_agent_string_id, #hep{capture_agent_string_id = Value}=Hep) ->
    do_make_chunk(Hep, ?CAPTURE_AGENT_STRING_ID, Value);

make_chunk (src_mac, #hep{src_mac = undefined}=_Hep) ->
    <<>>;
make_chunk (src_mac, #hep{src_mac = Value}=Hep) ->
    do_make_chunk(Hep, ?SOURCE_MAC, Value);

make_chunk (dst_mac, #hep{dst_mac = undefined}=_Hep) ->
    <<>>;
make_chunk (dst_mac, #hep{dst_mac = Value}=Hep) ->
    do_make_chunk(Hep, ?DESTINATION_MAC, Value);

make_chunk (ethernet_type, #hep{ethernet_type = undefined}=_Hep) ->
    <<>>;
make_chunk (ethernet_type, #hep{ethernet_type = Value}=Hep) ->
    do_make_chunk(Hep, ?ETHERNET_TYPE, <<?ethernet_type(Value)>>);

make_chunk (tcp_flag, #hep{tcp_flag = undefined}=_Hep) ->
    <<>>;
make_chunk (tcp_flag, #hep{tcp_flag = Value}=Hep) ->
    do_make_chunk(Hep, ?TCP_FLAG, Value);

make_chunk (ip_tos, #hep{ip_tos = undefined}=_Hep) ->
    <<>>;
make_chunk (ip_tos, #hep{ip_tos = Value}=Hep) ->
    do_make_chunk(Hep, ?IP_TOS, Value);

make_chunk (mos_value, #hep{mos_value = undefined}=_Hep) ->
    <<>>;
make_chunk (mos_value, #hep{mos_value = Value}=Hep) ->
    do_make_chunk(Hep, ?MOS_VALUE, <<?mos_value(Value)>>);

make_chunk (r_factor, #hep{r_factor = undefined}=_Hep) ->
    <<>>;
make_chunk (r_factor, #hep{r_factor = Value}=Hep) ->
    do_make_chunk(Hep, ?R_FACTOR, <<?r_factor(Value)>>);

make_chunk (geo_location, #hep{geo_location = undefined}=_Hep) ->
    <<>>;
make_chunk (geo_location, #hep{geo_location = Value}=Hep) ->
    do_make_chunk(Hep, ?GEO_LOCATION, Value);

make_chunk (jitter, #hep{jitter = undefined}=_Hep) ->
    <<>>;
make_chunk (jitter, #hep{jitter = Value}=Hep) ->
    do_make_chunk(Hep, ?JITTER, <<?jitter(Value)>>);

make_chunk (transaction_type, #hep{transaction_type = undefined}=_Hep) ->
    <<>>;
make_chunk (transaction_type, #hep{transaction_type = Value}=Hep) ->
    do_make_chunk(Hep, ?TRANSACTION_TYPE, Value);

make_chunk (payload_json_keys, #hep{payload_json_keys = undefined}=_Hep) ->
    <<>>;
make_chunk (payload_json_keys, #hep{payload_json_keys = Value}=Hep) ->
    do_make_chunk(Hep, ?PAYLOAD_JSON_KEYS, Value);

make_chunk (tags_values, #hep{tags_values = undefined}=_Hep) ->
    <<>>;
make_chunk (tags_values, #hep{tags_values = Value}=Hep) ->
    do_make_chunk(Hep, ?TAGS_VALUES, Value);

make_chunk (type_of_tag, #hep{type_of_tag = undefined}=_Hep) ->
    <<>>;
make_chunk (type_of_tag, #hep{type_of_tag = Value}=Hep) ->
    do_make_chunk(Hep, ?TYPE_OF_TAGS, <<?type_of_tag(Value)>>);

make_chunk (event_type, #hep{event_type = undefined}=_Hep) ->
    <<>>;
make_chunk (event_type, #hep{event_type = Value}=Hep) ->
    do_make_chunk(Hep, ?EVENT_TYPE, <<?event_type(Value)>>);

make_chunk (group_id, #hep{group_id = undefined}=_Hep) ->
    <<>>;
make_chunk (group_id, #hep{group_id = Value}=Hep) ->
    do_make_chunk(Hep, ?GROUP_ID, Value).


do_make_chunk (#hep{vendor = Vendor}, Type, Value) ->
    Len = byte_size(Value),
    <<?vendor((vendor(Vendor))), ?type(Type), ?length((2+2+2 + Len)), Value/binary>>.

%% End of Module.
