$Today = $(get-date).addDays(-30);$dateFilter ="created -gt '"+[string]$today.month+"/"+[string]$today.day+"/"+[string]$today.year+"'";
write-verbose "filter:",$dateFilter
$defaultDomain = "tdc.ad.teale.ca.gov"
$UserOU = "ou=OTech,ou=OCIO-Internal,ou=OCIO,ou=TDC,dc=tdc,dc=ad,dc=teale,dc=ca,dc=gov"
$foundMatches = get-aduser -Filter $dateFilter -properties created -server $defaultDomain -SearchBase $UserOU  | sort-object name | Select-Object name, userprincipalname, created
return $foundMatches