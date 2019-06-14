% This Source Code Form is subject to the terms of the Mozilla Public
% License, v. 2.0. If a copy of the MPL was not distributed with this
% file, You can obtain one at https://mozilla.org/MPL/2.0/.
% (C) 2019 Andrey Velikiy <agreat22@gmail.com>
% (C) 2019 Fairwaves (edited) 

-ifndef(IPA).
-define(IPA, true).

-define(IPAC_PROTO_OSMO, 16#ee).
-define(IPAC_PROTO_EXT_GSUP, 16#05).
-define(IPAC_PROTO_IPACCESS, 16#fe).
-define(IPAC_MSGT_PING, 0).
-define(IPAC_MSGT_PONG, 1).
-define(IPAC_MSGT_ID_GET, 4).
-define(IPAC_MSGT_ID_RESP, 5).
-define(IPAC_MSGT_ID_ACK, 6).

-endif.
