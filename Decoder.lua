--[[
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.
-- Copyright (c) 2014 Mozilla Corporation
--
-- Contributors:
-- Aalekh Nigam aalekh.nigam@gmail.com
local l = require 'lpeg'
l.locale(l)
local num = (l.digit^1 * "." * l.digit^1) / tonumber 
local name = l.R("AZ")^1*l.P("_")^-1* l.R("AZ")^0
local type = l.P("type=")*l.Cg(name,"Type")
local timestamp = l.P("msg=audit(")*l.Cg(num,"Timestamp")
local serial = l.P(":")*l.Cg(l.digit^1/tonumber,"serialnum") --Taking a integer for now

--local msgdata = l.P("):")*l.space^-1*l.Cg(l.P(1)^0,"Msgdata")


local space = l.space^0
local fieldname = l.C(l.alpha^1* (l.alnum + "-" + "_")^0)
local quoted = '"' * l.Cs(  (l.P'\\"' / '"' + (l.P(1) - '"'))^0  ) * '"'
local numeric = l.C(l.digit^1 * #l.space^1) / tonumber
local unquoted = l.C(l.alnum^1+ l.R"!~"^1)
local fieldvalue =  quoted + numeric + unquoted
local sep = space
local pair = l.Cg(fieldname * "=" * fieldvalue) * sep^-1
local tab = l.Cg(l.P("):")* space* l.Cf(l.Ct("") * pair^0, rawset),"Fields")

grammar = l.Ct(type*l.space^-1*timestamp*serial*tab)
]]--
local l = require 'lpeg'
l.locale(l)
local num = (l.digit^1 * "." * l.digit^1) / tonumber 
local name = l.R("AZ")^1*l.P("_")^-1* l.R("AZ")^0
local type = l.P("type=")*l.Cg(name,"Type")
local timestamp = l.P("msg=audit(")*l.Cg(num,"Timestamp")
local serial = l.P(":")*l.Cg(l.digit^1/tonumber,"Serialnum") --Taking a integer for now

--local msgdata = l.P("):")*l.space^-1*l.Cg(l.P(1)^0,"Msgdata")


local space = l.space^0
local fieldname = l.C(l.alpha^1* (l.alnum + "-" + "_")^0)
local quoted = '"' * l.Cs(  (l.P'\\"' / '"' + (l.P(1) - '"'))^0  ) * '"'
local numeric = l.C(l.digit^1 * #l.space^1) / tonumber
local unquoted = l.C(l.alnum^1+ l.R"!~"^1)
local fieldvalue =  quoted + numeric + unquoted
local sep = space
local pair = l.Cg(fieldname * "=" * fieldvalue) * sep^-1
local tab = l.Cg(l.P("):")* space* l.Cf(l.Ct("") * pair^0, rawset),"Fields")

grammar = l.Ct(type*l.space^-1*timestamp*serial*tab)
--local payload_keep = read_config("payload_keep")
function process_message()
    local log = read_message("Payload")

        --set a default msg that heka's
    --message matcher will ignore
    local msg = {
        Fields = {},
        Type = nil,
        Timestamp = nil,
        serialnum = nil
    }  
    local matches = grammar:match(log)
    if not matches then
        --return 0 to not propogate errors to heka's log.
        --return a message with IGNORE type to not match heka's message matcher
        inject_message(msg)
        return 0 
    end

    -- populating our fields
    msg['Type'] = read_config('type')
    msg['Logger'] = 'heka'
    msg['Severity'] = 'INFO'
    msg.Fields['exit'] = matches[0]
    msg.Fields['timestamp'] = matches[1]
    msg.Fields['hostname'] = matches[2]
    msg.Fields['program'] = matches[3]
    msg.Fields['processid'] = matches[4]
--    msg.Fields['debug'] = matches
    inject_message(msg)
    return 0
end
