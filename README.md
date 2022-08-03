# InBECstigation
InBECstigation - Approach to analyze BEC cases

# BEC/EAC Threat

This threat is related to the intrusion to financial and acquisitions communications where adversaries identify clue aspects for acquirement approvals. Adversaries identify the key participants from both sides in a negotiation and determine the moment to involve in the communications, mimicking themselves as the original participant. 
If the intromission is effective, the real participants won’t identify easily the changes and will continue the information exchange to accomplish all the needed data and procedures for the acquisition.
This intrusion is usually product of an initial phishing attack but can also be related to threat actor performing brute force or password guessing, public credentials dump from different services but identifying credentials reusage on multiple services or sometimes vulnerabilities related to mail services exposed over the internet and some cases in the companies’ premises.

# Implementing the algorithm using Jupyter notebook

By collecting domains and links in the message body and headers, and using command lines like whois, is it possible to identify fake domains involved in the communications and determine the date when the infrastructure was created, to add this information in the analysis timeline.

The first step is to load the evidence in a way that can be parsed and sorted based on real needs for investigation. Dealing with bit OST files or multiple email messages stored in a container it’s a difficult task and the best approach is to load all these information in lists that can be filtered based on metadata, headers and message content. Once information is parsed this way, it will be easy to look for threats or keywords that provide best information in a malleable format.

For this purpose, **Pypff** and **Extract_Msg** libraries from python allow to load a file (PST or msg) ang get all the metadata for analysis. Pypff  allows to iterating over all items in the root folder, analyze message by message and extract details for analysis without having to load the PST file in a mail client.

#Python Script

A python version for local execution has been implemented. Still needs improvements but can be used for initial assesment based on general metadata from messages.
