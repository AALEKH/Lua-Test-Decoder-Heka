--[[
local l = require 'lpeg'
l.locale(l)

local num = (l.digit^1 * "." * l.digit^1) / tonumber
local loadavg = l.Cg(num, "1MinAvg") *
    l.space * l.Cg(num, "5MinAvg") *
    l.space * l.Cg(num, "15MinAvg")
local procs = l.Cg(l.digit^1 / tonumber, "NumProcesses") * "/" * l.digit^1
local latestPid = l.digit^1

local grammar = lpeg.Ct(loadavg * l.space * procs * l.space * latestPid)
]]--
local l = require 'lpeg'
l.locale(l)
local num = (l.digit^1 * "." * l.digit^1) / tonumber 
local name = l.R("AZ")^1*l.P("_")^-1* l.R("AZ")^0
local type = l.P("type=")*l.Cg(name,"type")
local timestamp = l.P("msg=audit(")*l.Cg(num,"timestamp")
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
local text = l.Cg( (1-pair)^0 )*sep^-1

local newval = l.Cg(text^-1,"Message")*l.Cg( l.Cg(l.Cf(l.Ct("") * pair^0  ,rawset)) ,"Values")
local tab = l.P("):")* space*(newval)
local grammar = l.Ct(type*l.space^-1*timestamp*serial*tab)


local payload_keep = read_config("payload_keep")

local msg = {
    Type = "stats.loadavg",
    Message = nil,
    Values = nil
}

function process_message()
    local data = read_message("Messages")
    msg.Fields = grammar:match(data)

    if not msg.Fields then
        return -1
    end

    if payload_keep then
        msg.Payload = data
    end

    msg.Values.Path = read_message("Values[Path]")
    msg.Values.Pid = read_message("Values[Pid]")
    msg.Values.Coom = read_message("Values[Coom]")
    msg.Values.Dev = read_message("Values[Dev]")
    inject_message(msg)
    return 0
end
