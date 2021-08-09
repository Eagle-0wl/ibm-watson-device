module("luci.controller.ibm_controller", package.seeall)

function index()
	entry({"admin", "services", "ibm_model"}, cbi("ibm_model"), _("IBM Cloud"),105)
end

