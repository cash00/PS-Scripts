# Assign the CSV and XML Output File Paths
$XML_Path = "C:\Temp\Sample.xml"

# Create the XML File Tags
$xmlWriter = New-Object System.XMl.XmlTextWriter($XML_Path,$Null)
$xmlWriter.Formatting = 'Indented'
$xmlWriter.Indentation = 1
$XmlWriter.IndentChar = "`t"
$xmlWriter.WriteStartDocument()
$xmlWriter.WriteComment('Get the Information about the web application')
$xmlWriter.WriteStartElement('WebApplication')
$xmlWriter.WriteEndElement()
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()
      
      
# Create the Initial  Node
$xmlDoc = [System.Xml.XmlDocument](Get-Content $XML_Path);
$siteCollectionNode = $xmlDoc.CreateElement("SiteCollections")
$xmlDoc.SelectSingleNode("//WebApplication").AppendChild($siteCollectionNode)
$xmlDoc.Save($XML_Path)
      
$xmlDoc = [System.Xml.XmlDocument](Get-Content $XML_Path);
$siteCollectionNode = $xmlDoc.CreateElement("SiteCollection")
$xmlDoc.SelectSingleNode("//WebApplication/SiteCollections").AppendChild($siteCollectionNode)
$siteCollectionNode.SetAttribute("Name", "SiteCollectionTitle")
$siteCollectionNode.SetAttribute("value", "3c6250da5edf6b2e8d1a3930aa97a444bf3ba3de")
      
      
$subSitesNode = $siteCollectionNode.AppendChild($xmlDoc.CreateElement("SubSites"));
$subSitesNode.SetAttribute("Count", "45")
$xmlDoc.Save($XML_Path)
      
$subSiteNameNode = $subSitesNode.AppendChild($xmlDoc.CreateElement("SubSite"));
$subSiteNameNode.SetAttribute("Title", "Web title")
      
$ListsElement = $subSiteNameNode.AppendChild($xmlDoc.CreateElement("Lists"));
$ListElement = $ListsElement.AppendChild($xmlDoc.CreateElement("List"));
$ListElement.SetAttribute("Title", "ListTitle")
      
$RootFolderElement = $ListElement.AppendChild($xmlDoc.CreateElement("RootFolder"));
$RootFolderTextNode = $RootFolderElement.AppendChild($xmlDoc.CreateTextNode("Root folder Title"));
      
$xmlDoc.Save($XML_Path)

gc "C:\Temp\Sample.xml"
