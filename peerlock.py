#!/usr/bin/env python
"""
    Peerlock test program

    2016, Job Snijders <job@ntt.net>
"""

"""
    This program needs two database tables:
        - the rules
        - the peerings
"""

# filter rules
# XXX: THIS SHOULD BE FED FROM YOUR DATABASE
filter_table = {
    1: {'protected_asn': 174, 'allowed_upstream': None, 'in_what_region': 'everywhere'},
    2: {'protected_asn': 1299, 'allowed_upstream': None, 'in_what_region': 'everywhere'},
    3: {'protected_asn': 3356, 'allowed_upstream': None, 'in_what_region': 'everywhere'},
    4: {'protected_asn': 7018, 'allowed_upstream': None, 'in_what_region': 'everywhere'},
    5: {'protected_asn': 3491, 'allowed_upstream': 3356, 'in_what_region': 'everywhere'},
    6: {'protected_asn': 6830, 'allowed_upstream': 1299, 'in_what_region': 'everywhere'},
    7: {'protected_asn': 6830, 'allowed_upstream': 3356, 'in_what_region': 'everywhere'},
    8: {'protected_asn': 2914, 'allowed_upstream': None, 'in_what_region': 'everywhere'},
    9: {'protected_asn': 65000, 'allowed_upstream': 2914, 'in_what_region': 'europe'}
}

# neighbors per router, each router also symbolizes a region
# in reality we'd have multiple routers per region
# XXX: THIS SHOULD BE FED FROM YOUR DATABASE
network_topology = {
    'rtr_north_america': [101, 102, 103, 104, 202, 500, 174, 1299, 3356, 3549,
                          6762, 7018, 3491, 6830, 1239, 2914],
    'rtr_europe': [101, 102, 103, 201, 600, 174, 1299, 2914, 3356, 3549, 6762,
                   3491, 6830, 1239, 65000],
    'rtr_asia': [101, 102, 104, 201, 700, 3356, 6762, 3491, 38561, 1239, 2914],
    'rtr_south_america': [101, 800, 2914]
}

# command line arguments
import sys
if len(sys.argv) < 2:
    print "INFO: use -h for options"
    sys.exit()
if sys.argv[1] in ["-h", "--help"]:
    print "-X for IOX output"
    print "-J for JunOS output"
    sys.exit(0)
elif sys.argv[1] == "-X":
    vendor = "IOX"
elif sys.argv[1] == "-J":
    vendor = "JunOS"
else:
    print "INFO: use -h for options"

print "INFO: generating towards vendor %s" % vendor


# shorthand function for easy access to variables
def invert_topology(topology):
    result = {}
    for router in topology:
        for asn in topology[router]:
            if not asn in result:
                result[asn] = [router]
            else:
                result[asn].append(router)
    return result

# inverted topology is useful to test the constraints
inverted_topology = invert_topology(network_topology)

# test the filter rules
for rule in filter_table:
    protected_asn = filter_table[rule]['protected_asn']
    allowed_upstream = filter_table[rule]['allowed_upstream']
    region = filter_table[rule]['in_what_region']

    """
    constraint 2:
    only ASNs that connect with your network in multiple regions are eligible
    to be used as an allowed_upstream.
    """
    if allowed_upstream:

        if len(inverted_topology[allowed_upstream]) < 2:
            print "ERROR: constraint 2: in filter rule %s: %s is listed as \
allowed_upstream but not connected in multiple regions" \
                % (rule, allowed_upstream)

        else:
            print "OK: constraint 1: rule %s: allowed_upstream %s connects in \
enough regions: %s" \
                % (rule, allowed_upstream,
                   ", ".join(inverted_topology[allowed_upstream]))

    """
    constraint 3:
    allowed_upstream can only be set to "none" in combination with
    in_what_region "everywhere" if the protected_asn connects with your network
    in multiple regions. (like filter_rule #2, #5)

    NOTE: exceptions need to be allowed, for instance if you only peer in 1
    region in US, so in some cases we need to relax this requirement to
    "multiple interconnects within a single region.
    """
    if not allowed_upstream and region == "everywhere":

        if len(inverted_topology[protected_asn]) < 2:
            print "ERROR: constraint 3: in filter rule %s: protected_asn %s \
is not connected in enough regions." % (rule, protected_asn)

        else:
            print "OK: constraint 3: rule %s: protected_asn %s connects in %s" \
                % (rule, protected_asn,
                   ", ".join(inverted_topology[protected_asn]))

    """
    constraint 4:
    an allowed_upstream can only be specified for a region if the ASN also
    connects with your network in that region. (you cannot whitelist Y in
    region Z, if there is no YOU<>Y eBGP session in region Z)
    """
    if not region == "everywhere" and allowed_upstream:
        if not "rtr_%s" % region in inverted_topology[allowed_upstream]:
            print "ERROR: constraint 4: in filter rule %s: specified \
allowed_upstream %s is not connected in region %s" \
                % (rule, allowed_upstream, region)
        else:
            print "OK: constraint 4: rule %s: allowed_upstream %s connects \
in %s" % (rule, allowed_upstream, region)

print ""
print "INFO: tested all rules, router configs will follow:"
print ""

# compile list of all ASNs we will block in the eBGP inbound
# later on in the code we remove entries from this list
all_protected_asns = []
for entry in filter_table:
    if filter_table[entry]['protected_asn'] not in all_protected_asns:
        all_protected_asns.append(filter_table[entry]['protected_asn'])

# compile a list of ASNs that have filter rule(s) which only
# cover part of the world
not_global = all_protected_asns[:]
for asn in all_protected_asns:
    is_global = False
    for rule in filter_table:
        if filter_table[rule]['protected_asn'] == asn:
            if filter_table[rule]['in_what_region'] == "everywhere":
                is_global = True
    if is_global:
        not_global.remove(asn)

if vendor == "JunOS":
# iterate over each router
    for router in network_topology:
        print "router: %s" % router
        print "  policy-options {"
        # iterate over each neighbor connected to a router
        for neighbor in network_topology[router]:
            print "    as-path lock-AS%s-in \".*" % (neighbor),

            # list of protected_asns we will deny
            blocked_asns = all_protected_asns[:]
            to_delete = []
            no_match = True

            for rule in filter_table:
                """
                    Dear reader, thank you for reading this far, my apologies.
                    I sincerely wish I studied formal logic or an equivalent
                    in university instead of psychology. The below trainwreck
                    code is terrible. - Job
                """

                protected_asn = filter_table[rule]['protected_asn']
                allowed_upstream = filter_table[rule]['allowed_upstream']
                region = filter_table[rule]['in_what_region']
                # neighbor
                # router / region

                # will not filter the peer itself on direct sessions
                if protected_asn == neighbor:
                    to_delete.append(protected_asn)

                # honor region whitelisting
                elif neighbor == allowed_upstream and (region in router or region == "everywhere"):
                    to_delete.append(protected_asn)

                # FIXME from rule8
                # the default is to allow .* but we somehow need override or
                # combine when two rules overlap in that one specifies a region
                # and the other is "everywhere"
                # elif $something

                # when rules only cover a portion of the planet we need to allow
                # the ASN (for instance AS 202 is only protected in North America,
                # accept in rest of world)
                elif region not in router and protected_asn in not_global:
                    to_delete.append(protected_asn)

#            else:
#                print "LOOP 2: rule: %s, router: %s, neighbor: %s, protected_asn: %s, allowed: %s, region: %s" \
#                    % (rule, router, neighbor, protected_asn, allowed_upstream, region)


            blocked_asns = sorted(set(blocked_asns) - set(to_delete))
            print "(%s) .*\";" % "|".join(map(str, blocked_asns))
        print "  }"
        print ""

# YOLO no recycling of logic, direct exposure of logic output into printed
# output. But this is a proof of concept after all :-)
if vendor == "IOX":
    for router in network_topology:
        print "router: %s" % router
        for neighbor in network_topology[router]:
            print "  as-path-set lock-AS%s-in" % (neighbor)
            blocked_asns = all_protected_asns[:]
            to_delete = []
            no_match = True

            for rule in filter_table:
                protected_asn = filter_table[rule]['protected_asn']
                allowed_upstream = filter_table[rule]['allowed_upstream']
                region = filter_table[rule]['in_what_region']

                if protected_asn == neighbor:
                    to_delete.append(protected_asn)

                elif neighbor == allowed_upstream and (region in router or region == "everywhere"):
                    to_delete.append(protected_asn)

                elif region not in router and protected_asn in not_global:
                    to_delete.append(protected_asn)

            blocked_asns = sorted(set(blocked_asns) - set(to_delete))
            for protected in map(str, blocked_asns[:-1]):
                print "    ios-regex '_%s_',"% protected
            print "    ios-regex '_%i_'" % blocked_asns[-1:][0]
            print "  end-set"
            print "  !"
        print ""
