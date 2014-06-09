using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using NetFwTypeLib;

namespace NetSpamLock
{
    class Program
    {
        /// <summary>
        /// Structure to hold GEO IP information.
        /// </summary>
        public class GeoInfo
        {
            public string Ip;
            public string CountryName;
            public string RegionName;
            public string City;
        }

        /// <summary>
        /// Program entry point.
        /// </summary>
        /// <param name="args"></param>
        private static void Main(string[] args)
        {
            var doSilent = false;
            var doList = false;

            if (args.Length > 0)
            {
                switch (args[0])
                {
                    case "-s":
                        doSilent = true;
                        break;

                    case "-l":
                        doList = true;
                        break;

                    case "-h":
                    case "-help":
                        Console.WriteLine("Khaos NetSpamLock v2.0\n");
                        Console.WriteLine("Usage: netspamlock [-s | -l]");
                        Console.WriteLine("\t-s\tSilently scan and block malicious connections.");
                        Console.WriteLine("\t-l\tList all current connections sorted by connection number.");
                        Environment.Exit(0);
                        break;
                }
            }

            if (doSilent)
            {
                // Do silent scan and block
                var ips = GetRemoteAddresses();
                var connectionThreshold = uint.Parse(ConfigurationManager.AppSettings["ConnectionNumberThreshold"]);
                var maliciousIPs =
                    new HashSet<IPAddress>(ips.Where(x => x.Value >= connectionThreshold).Select(x => x.Key));

                // Log blocked addresses
                File.AppendAllLines("Blocked.log",
                    maliciousIPs.Select(
                        x => String.Format("{0}\t{1}", DateTime.Now, x)));

                // Block malicious IPs
                BlockAddresses(maliciousIPs);
            }
            else if (doList)
            {
                // Print list of all active connections
                var ips = GetRemoteAddresses().OrderByDescending(x => x.Value).ToList();
                Console.WriteLine("List of active connections by number:");
                ips.ForEach(x => Console.WriteLine("{0}\t{1}", x.Value, x.Key));
                Console.WriteLine();
            }
            else
            {
                // No options specified -- enter interactive mode
                Console.WriteLine("NetSpamLock Interactive Shell\n");

                while (true)
                {
                    Console.Write("netspamlock> ");
                    var query = Console.ReadLine();

                    if (String.IsNullOrWhiteSpace(query))
                    {
                        continue;
                    }

                    var split = query.Split(' ');

                    switch (split[0].ToLower())
                    {
                        case "list":
                            var ips = GetRemoteAddresses().OrderByDescending(x => x.Value).ToList();
                            Console.WriteLine("List of active connections by number:");
                            ips.ForEach(x => Console.WriteLine("{0}\t{1}", x.Value, x.Key));
                            Console.WriteLine();
                            break;

                        case "isin":
                            throw new NotImplementedException();
                            break;

                        case "unblock":
                            throw new NotImplementedException();
                            break;
                            
                        case "block":
                            throw new NotImplementedException();
                            break;

                        case "geo":
                            throw new NotImplementedException();
                            break;

                        case "geoblocked":
                            throw new NotImplementedException();
                            break;

                        case "help":
                            Console.WriteLine("Interactive shell commands overview.");
                            Console.WriteLine();
                            Console.WriteLine("list\t\tList all active connections sorted by their count from one IP.");
                            Console.WriteLine("isin {IP}\tFind if specified IP was blacklisted.");
                            Console.WriteLine("unblock {IP}\tDelete specified IP from the blocklist.");
                            Console.WriteLine("block {IP}\tAdd specified IP to the blocklist.");
                            Console.WriteLine("geo {IP}\tSearch for GEO-IP information about specified address.");
                            Console.WriteLine("geoblocked\tSearches GEO-IP info for all currently blocked addresses.");
                            Console.WriteLine();
                            break;

                        case "exit":
                        case "quit":
                            Console.WriteLine("Bye!");
                            Environment.Exit(0);
                            break;

                        default:
                            Console.WriteLine("Unknown command, type 'help' for basic usage.\n");
                            break;
                    }
                }
            }
        }

        /// <summary>
        /// Fetches GEO-IP information about specified address.
        /// </summary>
        /// <param name="address">Address to look for.</param>
        /// <returns>GEO-IP information.</returns>
        public static GeoInfo GetGeo(IPAddress address)
        {
            string[] content;

            using (var webClient = new WebClient())
            {
                webClient.Headers.Add("User-Agent: NetSpamLock/2.0");
                content = webClient.DownloadString(String.Format("http://freegeoip.net/csv/{0}", address)).Split(',');
            }

            if (content.Length != 11)
            {
                return null;
            }

            return new GeoInfo
            {
                Ip = content[0],
                CountryName = content[2],
                RegionName = content[4],
                City = content[5]
            };
        }

        /// <summary>
        /// Returns addresses of all currently connected remote machines.
        /// </summary>
        /// <returns>Currently connected IPs with information about number of simultaneous connections.</returns>
        public static Dictionary<IPAddress, uint> GetRemoteAddresses()
        {
            // Gather machine network statistic
            var ipProperties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = ipProperties.GetActiveTcpConnections();

            // Get self and non-consistent IPs
            var selfIps = Dns.GetHostEntry(Dns.GetHostName()).AddressList.ToList();
            selfIps.Add(IPAddress.Any);
            selfIps.Add(IPAddress.None);
            selfIps.Add(IPAddress.Loopback);
            //selfIps.Add(IPAddress.Broadcast);
            selfIps.Add(IPAddress.IPv6Any);
            //selfIps.Add(IPAddress.IPv6None);
            selfIps.Add(IPAddress.IPv6Loopback);

            // Form a hashset of remote machines
            var ips = new Dictionary<IPAddress, uint>();

            // And filter gathered metrics
            foreach (
                var connection in
                    tcpConnections.Where(
                        connection => !selfIps.Any(selfIp => connection.RemoteEndPoint.Address.Equals(selfIp))))
            {
                if (!ips.ContainsKey(connection.RemoteEndPoint.Address))
                {
                    ips[connection.RemoteEndPoint.Address] = 0;
                }

                ips[connection.RemoteEndPoint.Address] += 1;
            }

            return ips;
        }

        /// <summary>
        /// Blocks a set of IP addresses through Windows firewall.
        /// </summary>
        /// <param name="addresses">A set of addresses.</param>
        public static void BlockAddresses(HashSet<IPAddress> addresses)
        {
            if (addresses == null || !addresses.Any())
            {
                return;
            }

            var firewallPolicy =
                (INetFwPolicy2) Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var addressesStrings = new HashSet<string>(addresses.Select(x => x.ToString()));
            var firewallRuleName = ConfigurationManager.AppSettings["FirewallRuleName"];

            try
            {
                // Find existing rule and modify it
                var firewallRule = firewallPolicy.Rules.Item(firewallRuleName);

                // Accumulate all prevoius rules in hashset
                foreach (var address in firewallRule.RemoteAddresses.Split(','))
                {
                    addressesStrings.Add(address);
                }

                // Restore settings if it was messed
                firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                firewallRule.Enabled = true;
                firewallRule.InterfaceTypes = "All";

                // Set all rules back
                firewallRule.RemoteAddresses = String.Join(",", addressesStrings);
            }
            catch (FileNotFoundException)
            {
                // Create a rule if it does not exists
                var firewallRule = (INetFwRule) Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
                firewallRule.Name = firewallRuleName;
                firewallRule.Description = "Rule added by NetSpamLock to ban malicious IPs.";
                firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                firewallRule.Enabled = true;
                firewallRule.InterfaceTypes = "All";
                firewallRule.RemoteAddresses = String.Join(",", addressesStrings);
                firewallPolicy.Rules.Add(firewallRule);
            }
        }
    }
}
