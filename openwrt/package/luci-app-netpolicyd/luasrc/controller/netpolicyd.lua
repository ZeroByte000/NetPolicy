module("luci.controller.netpolicyd", package.seeall)

function index()
    entry({"admin", "services", "netpolicyd"}, template("netpolicyd/index"), _("NetPolicy"), 60).dependent = false
end
