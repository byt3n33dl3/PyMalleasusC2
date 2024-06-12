

![CatalanGate](https://i.postimg.cc/5ym5btDj/catalangate.png)

## Author
> #### Jonathan Scott - @jonathandata1
> #### Date: May 16th, 2022
# Research Introduction

###  April 18, 2022 The Citizen Lab posted research stating that they definitively concluded they had found Pegasus Spyware on the mobile devices of Catalonian government officials, their family members, journalists, and activists. 

### They specifically stated that there were 2 domains found on these mobile devices with a 100% match for a Pegasus Spyware infection. The specifics about how Citizen Lab came to the conclusion that these 2 domains were an exact match leading back to the NSO group and Pegasus is not known, nor do they provide information about it. 

### The 2 domains with a 100% positive match for infection if discovered on a mobile device are
 - https://www.nnews.co
 - https://www.123tramites.com
 
![CatalanGate](https://i.postimg.cc/gJxkGt5h/Screen-Shot-2022-05-16-at-3-57-08-PM.png)

**Source:** https://citizenlab.ca/2022/04/catalangate-extensive-mercenary-spyware-operation-against-catalans-using-pegasus-candiru/

### I wanted to find out how Citizen Lab was sure that a device was infected with Pegasus Spyware if these domains are found on a device. 
- How is the URL validated to be infectious?
- What does the infection look like?
- Where did Citizen Lab obtain the information confirming the malicious URLs?

## Finding The Origin of Detection

### Citizen Lab and Amnesty jointly released a spyware detection tool named "MVT" or Mobile Verification Toolkit. The toolkit contains IOCs or indicators of compromise, and here we can find one of the absolute confirmed malicious URLs 123tramites.com. Below is a code snippet showing Amnesty and Citizen Lab providing the IOCs. 

    [
        {
            "name": "NSO Group Pegasus Indicators of Compromise",
            "source": "Amnesty International",
            "reference": "https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/",
            "stix2_url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2"
        },
        {
            "name": "Cytrox Predator Spyware Indicators of Compromise",
            "source": "Meta, Amnesty International, Citizen Lab",
            "reference": "https://citizenlab.ca/2021/12/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/",
            "stix2_url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-12-16_cytrox/cytrox.stix2"
        }
    ]
![CatalanGate](https://i.postimg.cc/qBY66yx0/Screen-Shot-2022-05-16-at-4-03-06-PM.png)


**Sources:**
- https://github.com/mvt-project/mvt
- https://github.com/mvt-project/mvt/blob/main/public_indicators.json
- https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2

### The MVT-Tool specifically states in the code

> **This module looks extracts records from WebKit LocalStorage folders, and checks them against any provided list of suspicious domains**

**Source**: https://github.com/mvt-project/mvt/blob/main/mvt/ios/modules/fs/webkit_safariviewservice.py

### The base of the website detection tool specifically states that if a website is found in the backup that matches with the IOC mark the result as positive. It is clear that the only logic implemented to confirm a device has been infected is checking to see if keyword strings match.

    class WebkitBase(IOSExtraction):  
        """This class is a base for other WebKit-related modules."""  
      
      def check_indicators(self):  
            if not self.indicators:  
                return  
      
     for result in self.results:  
                ioc = self.indicators.check_domain(result["url"])  
                if ioc:  
                    result["matched_indicator"] = ioc  
                    self.detected.append(result)  
      
        def _process_webkit_folder(self, root_paths):  
            for found_path in self._get_fs_files_from_patterns(root_paths):  
                key = os.path.relpath(found_path, self.base_folder)  
      
                for name in os.listdir(found_path):  
                    if not name.startswith("http"):  
                        continue  
      
      name = name.replace("http_", "http://")  
                    name = name.replace("https_", "https://")  
                    url = name.split("_")[0]  
      
                    self.results.append({  
                        "folder": key,  
      "url": url,  
      "isodate": convert_timestamp_to_iso(datetime.datetime.utcfromtimestamp(os.stat(found_path).st_mtime)),  
      })

  
**Source**: https://github.com/mvt-project/mvt/blob/main/mvt/ios/modules/fs/webkit_base.py

# Setting Up The Experiment

> For this experiment we are going to focusing on iOS just as Citizen Lab did according to their CatalanGate report. 
 
 1. I found that the running the experiment via a docker image was easiest, and did not produce any errors when installing the MVT-Tool. I used an excellent repo from Defensive Lab Agency to help with the setup. https://defensive-lab.agency/2021/07/pegasus-ios-forensic/ 
 2. Open your Safari Browser and go to the URL https://www.123tramites.com , you will get a blank page, but that is ok. Do not close the browser tab, it's ok if you switch apps. 
 3. Make sure you have WhatsApp installed on your mobile device, and ensure you have at least 1 contact on WhatsApp you can message.  
 4. Send the following URLs to someone in your WhatsApp contact list. The URLs being sent via WhatsApp can be found here: https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-12-16_cytrox/cytrox.stix2

![CatalanGate](https://i.postimg.cc/pXrfjPjb/Screen-Shot-2022-05-16-at-3-19-46-PM.png)

> **Steps 5-7 instructions are in the step #1 link**

5. Take an encrypted backup of your mobile phone. 
6. Once your backup is completed. Decrypt the backup
7. If you followed the instructions in step #1 you should have a folder named ioc. do the following
`cd ioc
wget https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-12-16_cytrox/cytrox.stix2`
8. Next you will run the "forensics tool," and notice that you now have positive results
```
mvt-ios check-backup -o checked --iocs ioc/pegasus.stix2 decrypted
```
```
mvt-ios check-backup -o checked --iocs ioc/cytrox.stix2 decrypted

```
## Safari False Positive Results


![CatalanGate](https://i.postimg.cc/XJHMY9my/pegasus-infection.png)

## WhatsApp False Positive Results

![CatalanGate](https://i.postimg.cc/gctdzPbB/Screen-Shot-2022-05-16-at-3-32-50-PM.png)

# Sample Results Output

### The results of the sample that was used with the MVT-Tool are available in the repository. It is evident that manipulation can be easy, and there is no validation occurring when checking for the indicators of compromise. 

### Your results folder "checked," should look as follows. 

![CatalanGate](https://i.postimg.cc/FzGsVfYy/Screen-Shot-2022-05-16-at-6-42-47-PM.png)