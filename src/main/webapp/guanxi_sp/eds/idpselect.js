/*
TODO
 - HTMLencoding
 
 - check list for browsers
    - Z axis
    - CSS and Javascript sanity
    - language
*/


/** @class IdP Selector UI */
function IdPSelectUI(){
    //
    // The following are parameters - see setupLocals to where there are
    // made into global (to the module) variables.
    //
    this.dataSource = '/Shibboleth.sso/DiscoFeed';    // Where to get the data from
    this.insertAtDiv = 'idpSelect';  // The div where we will insert the data
    this.defaultLanguage = 'en';     // Language to use if the browser local doesnt have a bundle
    this.myEntityID = null;          // If non null then this string must match the string provided in the DS parms
    this.preferredIdP = null;        // Array of entityIds to always show
    this.stripHost = true;           // false allows this to be a DS to non cohosted SPs.
    this.helpURL = 'https://spaces.internet2.edu/display/SHIB2/DSRoadmap';
    this.ie6Hack = null;             // An array of structures to disable when drawing the pull down (needed to 
                                     // handle the ie6 z axis problem
    this.samlIdPCookieTTL = 730;     // in days
    this.defaultLogo = 'flyingpiglogo.jpg';
    this.defaultLogoWidth = 90;
    this.defaultLogoHeight = 80 ;
    this.HTMLEncodeChars = "#%&():[]\`{}";
    //
    // The following should not be changed without changes to the css
    //
    this.maxPreferredIdPs = 3;
    this.maxIdPCharsButton = 33;
    this.maxIdPCharsDropDown = 58;

    this.minWidth = 20;
    this.minHeight = 20;
    this.maxWidth = 115;
    this.maxHeight = 69;
    this.bestRatio = Math.log(80 / 60);
    this.langBundles = {
    'en': {
        'fatal.divMissing': 'Supplied Div is not present in the DOM',
        'fatal.noXMLHttpRequest': 'Browser does not support XMLHttpRequest, unable to load IdP selection data',
        'fatal.wrongProtocol' : 'policy supplied to DS was not "urn:oasis:names:tc:SAML:profiles:SSO:idpdiscovery-protocol:single"',
        'fatal.wrongEntityId' : 'entityId supplied was wrong"',
        'fatal.noparms' : 'No parameters to to discovery session',
        'fatal.noReturnURL' : "No URL return parmeter provided",
        'idpPreferred.label': 'Use a preferred selection:',
        'idpEntry.label': 'Or enter your organization\'s name',
        'idpEntry.NoPreferred.label': 'Enter your organization\'s name',
        'idpList.label': 'Or select your organization from the list below',
        'idpList.NoPreferred.label': 'Select your organization from the list below',
        'idpList.defaultOptionLabel': 'Please select your organization...',
 'idpList.showList' : 'Allow me to pick from a list',
        'idpList.showSearch' : 'Allow me to specify the site',
        'submitButton.label': 'Continue',
        'helpText': 'Help',
        'defaultLogoAlt' : 'DefaultLogo'
        }
    };

    //
    // module locals
    //
    var idpData;
    var base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var idpSelectDiv;
    var lang;
    var majorLang;
    var defaultLang;
    var langBundle;
    var defaultLangBundle;
    var defaultLogo;
    var defaultLogoWidth;
    var defaultLogoHeight;
    var minWidth;
    var minHeight;
    var maxWidth;
    var maxHeight;
    var bestRatio;
    var HTMLEncodeChars;

    //
    // Parameters passed into our closure
    //
    var preferredIdP;
    var maxPreferredIdPs;
    var helpURL;
    var ie6Hack;
    var samlIdPCookieTTL;
    var maxIdPCharsDropDown;
    var maxIdPCharsButton;

    //
    // The cookie contents
    //
    var userSelectedIdPs;
    //
    // Anchors used inside autofunctions
    //
    var idpEntryDiv;
    var idpListDiv;
    var idpSelect;
    var listButton;
    
    //
    // local configuration
    //
    var idPrefix = 'idpSelect';
    var classPrefix = 'IdPSelect';
    var dropDownControl;

    //
    // DS protocol configuration
    //
    var returnString = '';
    var returnBase='';
    var returnParms= new Array();
    var returnIDParam = 'entityID';

    // *************************************
    // Public functions
    // *************************************
    
    /**
       Draws the IdP Selector UI on the screen.  This is the main
       method for the IdPSelectUI class.
    */
    this.draw = function(){
        idpSelectDiv = document.getElementById(this.insertAtDiv);
        if(!idpSelectDiv){
            fatal(getLocalizedMessage('fatal.divMissing'));
            return;
        }

        if (!setupLocals(this)) {
            return;
        }
        if (!load(this.dataSource)) {
            return;
        }
        idpData.sort(function(a,b) {return getLocalizedName(a).localeCompare(getLocalizedName(b));});
        /*
         * We are building the DOM, not HTML, so we don't need this.  
         * But just in case some browser decides to behave differently
         
        HTMLEncodeIdPData();
        */
        
        var idpSelector = buildIdPSelector();
        idpSelectDiv.appendChild(idpSelector);
        dropDownControl.draw();
    } ;
    
    // *************************************
    // Private functions
    //
    // Data Manipulation
    //
    // *************************************

    /**
       Copies the "parameters" in the function into namesspace local
       variables.  This means most of the work is done outside the
       IdPSelectUI object
    */

    var setupLocals = function (parent) {
        //
        // Copy parameters in
        //
        var suppliedEntityId;

        preferredIdP = parent.preferredIdP;
        maxPreferredIdPs = parent.maxPreferredIdPs;
        helpURL = parent.helpURL;
        ie6Hack = parent.ie6Hack;
        samlIdPCookieTTL = parent.samlIdPCookieTTL;
        defaultLogo = parent.defaultLogo;
        defaultLogoWidth = parent.defaultLogoWidth;
        defaultLogoHeight = parent.defaultLogoHeight;
        minWidth = parent.minWidth;
        minHeight = parent.minHeight;
        maxWidth = parent.maxWidth;
        maxHeight = parent.maxHeight;
        bestRatio = parent.bestRatio;
        maxIdPCharsButton =  parent.maxIdPCharsButton;
        maxIdPCharsDropDown = parent.maxIdPCharsDropDown;
        HTMLEncodeChars = AddMissingHTMLEncodeChars(parent.HTMLEncodeChars);

        if (typeof navigator == 'undefined') {
            lang = parent.defaultLanguage;
        } else {
            lang = navigator.language || navigator.userLanguage || parent.defaultLanguage;
        }
        if (lang.indexOf('-') > 0) {
            majorLang = lang.substring(0, lang.indexOf('-'));
        }

        defaultLang = parent.defaultLanguage;

        if (typeof parent.langBundles[lang] != 'undefined') {
            langBundle = parent.langBundles[lang];
        } else if (typeof majorLang != 'undefined' && typeof parent.langBundles[majorLang] != 'undefined') {
            langBundle = parent.langBundles[majorLang];
        }
        defaultLangBundle = parent.langBundles[parent.defaultLanguage];

        //
        // Setup Language bundles
        //
        if (!defaultLangBundle) {
            fatal('No languages work');
            return false;
        }
        if (!langBundle) {
            debug('No language support for ' + lang);
        }

        if (parent.testGUI) {
            //
            // no policing of parms
            //
            return true;
        }
        //
        // Now set up the return values from the URL
        //
        var win = window;
        while (null !== win.parent && win !== win.parent) {
            win = win.parent;
        }
        var loc = win.location;
        var parmlist = loc.search;
        if (null == parmlist || 0 == parmlist.length || parmlist.charAt(0) != '?') {

            fatal(getLocalizedMessage('fatal.noparms'));
            return false;
        }
        parmlist = parmlist.substring(1);

        //
        // protect against various hideousness by decoding. We re-encode just before we push
        //

        var parms = parmlist.split('&');
        if (parms.length == 0) {

            fatal(getLocalizedMessage('fatal.noparms'));
            return false;
        }
        var policy = 'urn:oasis:names:tc:SAML:profiles:SSO:idpdiscovery-protocol:single';
        var i;
        for (i = 0; i < parms.length; i++) {
            var parmPair = parms[i].split('=');
            if (parmPair.length != 2) {
                continue;
            }
            if (parmPair[0] == 'entityID') {
                suppliedEntityId = decodeURIComponent(parmPair[1]);
            } else if (parmPair[0] == 'return') {
                returnString = decodeURIComponent(parmPair[1]);
            } else if (parmPair[0] == 'returnIDParam') {
                returnIDParam = decodeURIComponent(parmPair[1]);
            } else if (parmPair[0] == 'policy') {
                policy = decodeURIComponent(parmPair[1]);
            } 
        }
        if (policy != 'urn:oasis:names:tc:SAML:profiles:SSO:idpdiscovery-protocol:single') {
            fatal(getLocalizedMessage('fatal.wrongProtocol'));
            return false
        }
        if (parent.myEntityID != null && parent.myEntityID != suppliedEntityId) {
            fatal(getLocalizedMessage('fatal.wrongEntityId') + '"' + suppliedEntityId + '" != "' + parent.myEntityID + '"');
            return false;
        }
        if (parent.stripHost) {
            returnString = stripHostName(returnString);
        }
        if (null == returnString || returnString.length == 0) {
            fatal(getLocalizedMessage('fatal.noReturnURL'));
            return false;
        }

        //
        // Now split up returnString
        //
        i = returnString.indexOf('?');
        if (i < 0) {
            returnBase = returnString;
            return true;
        }
        returnBase = returnString.substring(0, i);
        parmlist = returnString.substring(i+1);
        parms = parmlist.split('&');
        for (i = 0; i < parms.length; i++) {
            var parmPair = parms[i].split('=');
            if (parmPair.length != 2) {
                continue;
            }
            parmPair[1] = decodeURIComponent(parmPair[1]);
            returnParms.push(parmPair);
        }
        return true;
    };

    /**
     * Strip the "protocol://host" bit out of the URL
     * @param the URL to process
     * @return the URL without the protocol and host
     */

    var stripHostName = function(s) {
        if (null == s) {
            return s;
        }
        var marker = "://";
        var protocolEnd = s.indexOf(marker);
        if (protocolEnd < 0) {
            return s;
        }
        s = s.substring(marker.length + protocolEnd);
        marker = "/";
        var hostEnd = s.indexOf(marker);
        if (hostEnd < 0) {
            return s;
        }
        return s.substring(hostEnd);
    }

    /**
     * We need to cache bust on IE.  So how do we know?  Use a bigger hammer.
     */
    var isIE = function() {
        if (null == navigator) {
            return false;
        }
        var browserName = navigator.appName;
        if (null == browserName) {
            return false;
        }
        return (browserName == 'Microsoft Internet Explorer');
    }


    /**
       Loads the data used by the IdP selection UI.  Data is loaded 
       from a JSON document fetched from the given url.
      
       @param {Function} failureCallback A function called if the JSON
       document can not be loaded from the source.  This function will
       passed the {@link XMLHttpRequest} used to request the JSON data.
    */
    var load = function(dataSource){
        var xhr = new XMLHttpRequest();

        if (isIE()) {
            //
            // cache bust (for IE)
            //
            dataSource += '?random=' + (Math.random()*1000000);
        }

        //
        // Grab the data
        //
        xhr.open('GET', dataSource, false);
        if (typeof xhr.overrideMimeType == 'function') {
            xhr.overrideMimeType('application/json');
        }
        xhr.send(null);
        
        if(xhr.status == 200){
            //
            // 200 means we got it OK from as web source
            // if locally loading its 0.  Go figure
            //
            var jsonData = xhr.responseText;
            if(jsonData == ''){
                fatal('No data!');
                return false;
            }

            //
            // Parse it
            //

            idpData = JSON.parse(jsonData);

        }else{
            fatal('Could not download data from ' + dataSource);
            return false;
        }
        return true;
    };

    /**
       Returns the idp object with the given name.

       @param (String) the name we are interested in
       @return (Object) the IdP we care about
    */

    var getIdPFor = function(idpName) {

        for (var i = 0; i < idpData.length; i++) {
            if (getEntityId(idpData[i]) == idpName) {
                return idpData[i];
            }
        }
        return null;
    };

    /**
       Returns a suitable image from the given IdP
       
       @param (Object) The IdP
       @return Object) a DOM object suitable for insertion
       
       TODO - rather more careful selection
    */

    var getImageForIdP = function(idp) {

        var getBestFit = function(language) {
            //
            // See GetLocalizedEntry
            //
            var bestFit = null;
            var i;
            if (null == idp.Logos) {
                return null;
            }
            for (i in idp.Logos) {
                if (idp.Logos[i].lang == language &&
                    idp.Logos[i].width != null &&  
                    idp.Logos[i].width >= minWidth &&
                    idp.Logos[i].height != null && 
                    idp.Logos[i].height >= minHeight) {
                    if (bestFit == null) {
                        bestFit = idp.Logos[i];
                    } else {
                        me = Math.abs(bestRatio - Math.log(idp.Logos[i].width/idp.Logos[i].height));
                        him = Math.abs(bestRatio - Math.log(bestFit.width/bestFit.height));
                        if (him > me) {
                            bestFit = idp.Logos[i];
                        }
                    }
                }
            }
            return bestFit;
        }

        var bestFit = null
        var img = document.createElement('img');

        bestFit = getBestFit(lang);
        if (null == bestFit && typeof majorLang != 'undefined') {
            bestFit = getBestFit(majorLang);
        }
        if (null == bestFit) {
            bestFit = getBestFit(null);
        }
        if (null == bestFit) {
            bestFit = getBestFit(defaultLang);
        }
               

        if (null === bestFit) {
            img.src = defaultLogo;
            img.width = defaultLogoWidth;
            img.height = defaultLogoHeight;
            img.alt = getLocalizedMessage('defaultLogoAlt');
            return img;
        }

        img.src = bestFit.value;
        img.alt = getLocalizedName(idp);

        var w = bestFit.width;
        var h = bestFit.height;
        if (w>maxWidth) {
            h = (maxWidth/w) * h;
            w = maxWidth;
        }
        if (h> maxHeight) {
            w = (maxHeight/h) * w;
            w = maxHeight;
        }
            
        img.setAttribute('width', w);
        img.setAttribute('height', h);
        return img;
    };

    // *************************************
    // Private functions
    //
    // GUI Manipulation
    //
    // *************************************
    
    /**
       Builds the IdP selection UI.

       Three divs. PreferredIdPTime, EntryTile and DropdownTile
      
       @return {Element} IdP selector UI
    */
    var buildIdPSelector = function(){
        var containerDiv = buildDiv('IdPSelector');
        var preferredTileExists;
        preferredTileExists = buildPreferredIdPTile(containerDiv);
        buildIdPEntryTile(containerDiv, preferredTileExists);
        buildIdPDropDownListTile(containerDiv, preferredTileExists);
        return containerDiv;
    };

    /**
      Builds a button for the provided IdP
        <div class="preferredIdPButton">
          <a href="XYX" onclick=setparm('ABCID')>
            <div class=
            <img src="https:\\xyc.gif"> <!-- optional -->
            XYX Text
          </a>
        </div>

      @param (Object) The IdP
      
      @return (Element) preselector for the IdP
    */

    var composePreferredIdPButton = function(idp, uniq) {
        var div = buildDiv(undefined, 'PreferredIdPButton');
        var aval = document.createElement('a');
        var retString = returnIDParam + '=' + encodeURIComponent(getEntityId(idp));
        var retVal = returnString;
        var img = getImageForIdP(idp);
        //
        // Compose up the URL
        //
        if (retVal.indexOf('?') == -1) {
            retString = '?' + retString;
        } else {
            retString = '&' + retString;
        }
        aval.href = retVal + retString;
        aval.onclick = function () {
            selectIdP(getEntityId(idp));
        };
        var imgDiv=buildDiv(undefined, 'PreferredIdPImg');
        imgDiv.appendChild(img);
        aval.appendChild(imgDiv);

        var nameDiv = buildDiv(undefined, 'TextDiv');
        var nameStr = getLocalizedName(idp);
        div.title = nameStr;
        if (nameStr.length > maxIdPCharsButton) {
            nameStr = nameStr.substring(0, maxIdPCharsButton) + '...';
        }
        nameDiv.appendChild(document.createTextNode(nameStr));
        aval.appendChild(nameDiv);

        div.appendChild(aval);
        return div;
    };

    /**
     * Builds and populated a text Div
     */
    var buildTextDiv = function(parent, textId)
    {
        var div  = buildDiv(undefined, 'TextDiv');
        var introTxt = document.createTextNode(getLocalizedMessage(textId)); 
        div.appendChild(introTxt);
        parent.appendChild(div);
    }
    
    /**
       Builds the preferred IdP selection UI (top half of the UI w/ the
       IdP buttons)

       <div id=prefix+"PreferredIdPTile">
          <div> [see comprosePreferredIdPButton </div>
          [repeated]
       </div>
      
       @return {Element} preferred IdP selection UI
    */
    var buildPreferredIdPTile = function(parentDiv){

        var preferredIdPs = getPreferredIdPs();
        if (0 == preferredIdPs.length) {
            return false;
        }

        var preferredIdPDIV = buildDiv('PreferredIdPTile');

        buildTextDiv(preferredIdPDIV, 'idpPreferred.label');

        for(var i = 0 ; i < maxPreferredIdPs && i < preferredIdPs.length; i++){
            if (preferredIdPs[i]) {
                var button = composePreferredIdPButton(preferredIdPs[i],i);
                preferredIdPDIV.appendChild(button);
            }
        }

        parentDiv.appendChild(preferredIdPDIV);
        return true;
    };

    /**
     * Build the <form> from the return parameters
     */

    var buildSelectForm = function ()
    {
        var form = document.createElement('form');
        idpEntryDiv.appendChild(form);

        form.action = returnBase;
        form.method = 'GET';
        form.setAttribute('autocomplete', 'OFF');
        var i = 0;
        for (i = 0; i < returnParms.length; i++) {
            var hidden = document.createElement('input');
            hidden.setAttribute('type', 'hidden');
            hidden.name = returnParms[i][0];
            hidden.value= returnParms[i][1];
            form.appendChild(hidden);
        }

        return form;
    }        


    /**
       Build the manual IdP Entry tile (bottom half of UI with
       search-as-you-type field).

       <div id = prefix+"IdPEntryTile">
         <form>
           <input type="text", id=prefix+"IdPSelectInput/> // select text box
           <input type="hidden" /> param to send
           <input type="submit" />
           
      
       @return {Element} IdP entry UI tile
    */
    var buildIdPEntryTile = function(parentDiv, preferredTile) {

        idpEntryDiv = buildDiv('IdPEntryTile');

        if (preferredTile) {
            buildTextDiv(idpEntryDiv, 'idpEntry.label');
        } else {
            buildTextDiv(idpEntryDiv, 'idpEntry.NoPreferred.label');
        }

        var form = buildSelectForm();
      
        var textInput = document.createElement('input');
        form.appendChild(textInput);

        textInput.type='text';
        setID(textInput, 'Input');

        var hidden = document.createElement('input');
        hidden.setAttribute('type', 'hidden');
        form.appendChild(hidden);

        hidden.name = returnIDParam;
        hidden.value='-';

        var button = buildContinueButton('Select');
        button.disabled = true;
        form.appendChild(button);
        
        form.onsubmit = function () {
            //
            // Make sure we cannot ask for garbage
            //
            if (null === hidden.value || 0 == hidden.value.length || '-' == hidden.value) {
                return false;
            }
            //
            // And always ask for the cookie to be updated before we continue
            //
            textInput.value = hidden.textValue;
            selectIdP(hidden.value);
            return true;
        };

        dropDownControl = new TypeAheadControl(idpData, textInput, hidden, button, maxIdPCharsDropDown, getLocalizedName, getEntityId, geticon, ie6Hack);

        var a = document.createElement('a');
        a.appendChild(document.createTextNode(getLocalizedMessage('idpList.showList')));
        a.href = '#';
        setClass(a, 'DropDownToggle');
        a.onclick = function() { 
            idpEntryDiv.style.display='none';
            idpListDiv.style.display='inline';
            listButton.focus();
        };
        idpEntryDiv.appendChild(a);
        buildHelpText(idpEntryDiv);
                                              
        parentDiv.appendChild(idpEntryDiv);
    };
    
    /**
       Builds the drop down list containing all the IdPs from which a
       user may choose.

       <div id=prefix+"IdPListTile">
          <label for="idplist">idpList.label</label>
          <form action="URL from IDP Data" method="GET">
          <select name="param from IdP data">
             <option value="EntityID">Localized Entity Name</option>
             [...]
          </select>
          <input type="submit"/>
       </div>
        
       @return {Element} IdP drop down selection UI tile
    */
    var buildIdPDropDownListTile = function(parentDiv, preferredTile) {
        idpListDiv = buildDiv('IdPListTile');
        idpListDiv.style.display = 'none';

        if (preferredTile) {
            buildTextDiv(idpListDiv, 'idpList.label');
        } else {
            buildTextDiv(idpListDiv, 'idpList.NoPreferred.label');
        }

        idpSelect = document.createElement('select');
        setID(idpSelect, 'Selector');
        idpSelect.name = returnIDParam;
        idpListDiv.appendChild(idpSelect);
        
        var idpOption = buildSelectOption('-', getLocalizedMessage('idpList.defaultOptionLabel'));
        idpOption.selected = true;

        idpSelect.appendChild(idpOption);
    
        var idp;
        for(var i=0; i<idpData.length; i++){
            idp = idpData[i];
            idpOption = buildSelectOption(getEntityId(idp), getLocalizedName(idp));
            idpSelect.appendChild(idpOption);
        }

        var form = buildSelectForm();

        form.appendChild(idpSelect);

        form.onsubmit = function () {
            //
            // The first entery isn't selectable
            //
            if (idpSelect.selectedIndex < 1) {
                return false;
            }
            //
            // otherwise update the cookie
            //
            selectIdP(idpSelect.options[idpSelect.selectedIndex].value);
            return true;
        };

        var button = buildContinueButton('List');
        listButton = button;
        form.appendChild(button);

        idpListDiv.appendChild(form);

        //
        // The switcher
        //
        var a = document.createElement('a');
        a.appendChild(document.createTextNode(getLocalizedMessage('idpList.showSearch')));
        a.href = '#';
        setClass(a, 'DropDownToggle');
        a.onclick = function() { 
            idpEntryDiv.style.display='inline';
            idpListDiv.style.display='none';
        };
        idpListDiv.appendChild(a);
        buildHelpText(idpListDiv);

        parentDiv.appendChild(idpListDiv);
    };

    /**
       Builds the 'continue' button used to submit the IdP selection.
      
       @return {Element} HTML button used to submit the IdP selection
    */
    var buildContinueButton = function(which) {
        var button  = document.createElement('input');
        button.setAttribute('type', 'submit');
        button.value = getLocalizedMessage('submitButton.label');
        setID(button, which + 'Button');

        return button;
    };

    /**
       Builds an aref to point to the helpURL
    */

    var buildHelpText = function(containerDiv) {
        var aval = document.createElement('a');
        aval.href = helpURL;
        aval.appendChild(document.createTextNode(getLocalizedMessage('helpText')));
        setClass(aval, 'HelpButton');
        containerDiv.appendChild(aval);
    }
    
    /**
       Creates a div element whose id attribute is set to the given ID.
      
       @param {String} id ID for the created div element
       @param {String} [class] class of the created div element
       @return {Element} DOM 'div' element with an 'id' attribute
    */
    var buildDiv = function(id, whichClass){
        var div = document.createElement('div');
        if (undefined != id) {
            setID(div, id);
        }
        if(undefined != whichClass) {

            setClass(div, whichClass);
        }
        return div;
    };
    
    /**
       Builds an HTML select option element
      
       @param {String} value value of the option when selected
       @param {String} label displayed label of the option
    */
    var buildSelectOption = function(value, text){
        var option = document.createElement('option');
        option.value = value;
        if (text.length > maxIdPCharsDropDown) {
            text = text.substring(0, maxIdPCharsDropDown);
        }
        option.appendChild(document.createTextNode(text));
        return option;
    };
    
    /**
       Sets the attribute 'id' on the provided object
       We do it through this function so we have a single
       point where we can prepend a value
       
       @param (Object) The [DOM] Object we want to set the attribute on
       @param (String) The Id we want to set
    */

    var setID = function(obj, name) {
        obj.id = idPrefix + name;
    };

    var setClass = function(obj, name) {
        obj.setAttribute('class', classPrefix + name);
    }

    /**
       Returns the DOM object with the specified id.  We abstract
       through a function to allow us to prepend to the name
       
       @param (String) the (unprepended) id we want
    */
    var locateElement = function(name) {
        return document.getElementById(idPrefix + name);
    };

    // *************************************
    // Private functions
    //
    // GUI actions.  Note that there is an element of closure going on
    // here since these names are invisible outside this module.
    // 
    //
    // *************************************

    /**
     * Base helper function for when an IdP is selected
     * @param (String) The UN-encoded entityID of the IdP
    */

    var selectIdP = function(idP) {
        updateSelectedIdPs(idP);
        saveUserSelectedIdPs(userSelectedIdPs);
    };

    // *************************************
    // Private functions
    //
    // Localization handling
    //
    // *************************************

    /**
       Gets a localized string from the given language pack.  This
       method uses the {@link langBundles} given during construction
       time.

       @param {String} messageId ID of the message to retrieve

       @return (String) the message
    */
    var getLocalizedMessage = function(messageId){

        var message = langBundle[messageId];
        if(!message){
            message = defaultLangBundle[messageId];
        }
        if(!message){
            message = 'Missing message for ' + messageId;
        }
        
        return message;
    };

    var getEntityId = function(idp) {
        return idp.entityID;
    }

    /**
       Returns the icon information for the provided idp

       @param (Object) an idp.  This should have an array 'names' with sub
        elements 'lang' and 'name'.

       @return (String) The localized name
    */
    var geticon = function(idp) {
        var i;

        for (i in idp.Logos) {
	    var logo = idp.Logos[i];

	    if (logo.height == "16" && logo.width == "16") {
		if (null == logo.lang ||
		    lang == logo.lang ||
		    (typeof majorLang != 'undefined' && majorLang == logo.lang) ||
		    defaultLang == logo.lang) {
		    return logo.value;
		}
	    }
	}

	return null;
    }

    /**
       Returns the localized name information for the provided idp

       @param (Object) an idp.  This should have an array 'names' with sub
        elements 'lang' and 'name'.

       @return (String) The localized name
    */
    var getLocalizedName = function(idp) {
        var res = getLocalizedEntry(idp.DisplayNames);
        if (null != res) {
            return res;
        }
        debug('No Name entry in any language for ' + getEntityId(idp));
        return getEntityId(idp);
    }

    var getLocalizedEntry = function(theArray){
        var i;

        //
        // try by full name
        //
        for (i in theArray) {
            if (theArray[i].lang == lang) {
                return theArray[i].value;
            }
        }
        //
        // then by major language
        //
        if (typeof majorLang != 'undefined') {
            for (i in theArray) {
                if (theArray[i].lang == majorLang) {
                    return theArray[i].value;
                }
            }
        }
        //
        // then by null language in metadata
        //
        for (i in theArray) {
            if (theArray[i].lang == null) {
                return theArray[i].value;
            }
        }
        
        //
        // then by default language
        //
        for (i in theArray) {
            if (theArray[i].lang == defaultLang) {
                return theArray[i].value;
            }
        }

        return null;
    };

    
    // *************************************
    // Private functions
    //
    // Cookie and preferred IdP Handling
    //
    // *************************************

    /**
       Gets the preferred IdPs.  The first elements in the array will
       be the preselected preferred IdPs.  The following elements will
       be those past IdPs selected by a user.  The size of the array
       will be no larger than the maximum number of preferred IdPs.
    */
    var getPreferredIdPs = function(){
        var idps = new Array();
        var offset = 0;
        var i;
        var j;

        //
        // populate start of array with preselected IdPs
        //
        if(preferredIdP){
            for(i=0; i < preferredIdP.length && i < maxPreferredIdPs-1; i++){
                idps[i] = getIdPFor(preferredIdP[i]);
                offset++;
            }
        }
        
        //
        // And then the cookie based ones
        //
        userSelectedIdPs = retrieveUserSelectedIdPs();
        for (i = offset, j=0; i < userSelectedIdPs.length && i < maxPreferredIdPs; i++, j++){
            idps.push(getIdPFor(userSelectedIdPs[j]));
        }
        return idps;
    };

    /**
       Update the userSelectedIdPs list with the new value.

       @param (String) the newly selected IdP
    */
    var updateSelectedIdPs = function(newIdP) {

        //
        // We cannot use split since it does not appear to
        // work as per spec on ie8.
        //
        var newList = [];

        //
        // iterate through the list copying everything but the old
        // name
        //
        while (0 != userSelectedIdPs.length) {
            var what = userSelectedIdPs.pop();
            if (what != newIdP) {
                newList.unshift(what);
            }
        }

        //
        // And shove it in at the top
        //
        newList.unshift(newIdP);
        userSelectedIdPs = newList;
        return;
    };
    
    /**
       Gets the IdP previously selected by the user.
      
       @return {Array} user selected IdPs identified by their entity ID
    */
    var retrieveUserSelectedIdPs = function(){
        var userSelectedIdPs = new Array();
        var i, j;
        var cookies;

        cookies = document.cookie.split( ';' );
        for (i = 0; i < cookies.length; i++) {
            //
            // Do not use split('='), '=' is valid in Base64 encoding!
            //
            var cookie = cookies[i];
            var splitPoint = cookie.indexOf( '=' );
            var cookieName = cookie.substring(0, splitPoint);
            var cookieValues = cookie.substring(splitPoint+1);
                                
            if ( '_saml_idp' == cookieName.replace(/^\s+|\s+$/g, '') ) {
                cookieValues = cookieValues.replace(/^\s+|\s+$/g, '').split('+');
                for(j=0; j< cookieValues.length; j++){
                    if (0 == cookieValues[j].length) {
                        continue;
                    }
                    var dec = base64Decode(decodeURIComponent(cookieValues[j]));
                    if (dec.length > 0) {
                        userSelectedIdPs.push(dec);
                    }
                }
            }
        }

        return userSelectedIdPs;
    };
    
    /**
       Saves the IdPs selected by the user.
      
       @param {Array} idps idps selected by the user
    */
    var saveUserSelectedIdPs = function(idps){
        var cookieData = new Array();
        var length = idps.length;
        if (length > 5) {
            length = 5;
        }
        for(var i=0; i < length; i++){
            if (idps[i].length > 0) {
                cookieData.push(encodeURIComponent(base64Encode(idps[i])));
            }
        }
        
        var expireDate = null;
        if(samlIdPCookieTTL){
            var now = new Date();
            cookieTTL = samlIdPCookieTTL * 24 * 60 * 60 * 1000;
            expireDate = new Date(now.getTime() + cookieTTL);
        }
        
        document.cookie='_saml_idp' + '=' + cookieData.join('+') + '; path = /' +
            ((expireDate===null) ? '' : '; expires=' + expireDate.toUTCString());
    };
    
    /**
       Base64 encodes the given string.
      
       @param {String} input string to be encoded
      
       @return {String} base64 encoded string
    */
    var base64Encode = function(input) {
        var output = '', c1, c2, c3, e1, e2, e3, e4;

        for ( var i = 0; i < input.length; ) {
            c1 = input.charCodeAt(i++);
            c2 = input.charCodeAt(i++);
            c3 = input.charCodeAt(i++);
            e1 = c1 >> 2;
            e2 = ((c1 & 3) << 4) + (c2 >> 4);
            e3 = ((c2 & 15) << 2) + (c3 >> 6);
            e4 = c3 & 63;
            if (isNaN(c2)){
                e3 = e4 = 64;
            } else if (isNaN(c3)){
                e4 = 64;
            }
            output += base64chars.charAt(e1) +
                base64chars.charAt(e2) +
                base64chars.charAt(e3) + 
                base64chars.charAt(e4);
        }

        return output;
    };
    
    /**
       Base64 decodes the given string.
      
       @param {String} input string to be decoded
      
       @return {String} base64 decoded string
    */
    var base64Decode = function(input) {
        var output = '', chr1, chr2, chr3, enc1, enc2, enc3, enc4;
        var i = 0;

        // Remove all characters that are not A-Z, a-z, 0-9, +, /, or =
        var base64test = /[^A-Za-z0-9\+\/\=]/g;
        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');

        do {
            enc1 = base64chars.indexOf(input.charAt(i++));
            enc2 = base64chars.indexOf(input.charAt(i++));
            enc3 = base64chars.indexOf(input.charAt(i++));
            enc4 = base64chars.indexOf(input.charAt(i++));

            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;

            output = output + String.fromCharCode(chr1);

            if (enc3 != 64) {
                output = output + String.fromCharCode(chr2);
            }
            if (enc4 != 64) {
                output = output + String.fromCharCode(chr3);
            }

            chr1 = chr2 = chr3 = '';
            enc1 = enc2 = enc3 = enc4 = '';

        } while (i < input.length);

        return output;
    };

    //
    // HTML encoding functions
    //

    /**
     *  AddMissingHTMLEncodeChars 
     *  make sure that <,>,&,",',\ are alwats escaped
     */ 
    var AddMissingChar = function (inString, theChar) {
        if (inString.indexOf(theChar) < 0) {
            inString = theChar + inString;
        }
        return inString;
    }

    var AddMissingHTMLEncodeChars = function(inString)
    {
        //
        // and add the "always encode" ones
        //
        inString = AddMissingChar(inString,"<");
        inString = AddMissingChar(inString,">");
        inString = AddMissingChar(inString,"&");
        inString = AddMissingChar(inString,"'");
        inString = AddMissingChar(inString,'"');
        inString = AddMissingChar(inString,"\\");
        return inString
    }            

    /**
     * hasEncodingChars
     * Does the string contain any html encoding chars
     * @param theString - The string under question 
     * @return -1 if the string has no encoding chars
     * otherwise returns the index of the first char met
     */
    var hasEncodingChars = function(theString)
    {
        var i;
        for (i = 0; i < theString.length; i++) {
            var pos =  HTMLEncodeChars.indexOf(theString.charAt(i));
            if (pos > 0 ) {
                return i;
            }
        }
        return -1;
    }

    /**
     * HTMLEncode
     * HTML encode the provided string, with a hint to where to start
     * the encoding
     * @param theString - string to encode
     * @param hint - the index of the first char to encode
     * @return HTML encoded string
     */
    var HTMLEncode = function(theString, hint) {
        var retString = theString.substring(0,hint);
        var i = 0;

        for (i = hint; i < theString.length; i++) {
            var theChar = theString.charCodeAt(i);
            var nextSegment = theString.charAt(i);
            var j;
            for (j = 0; j < HTMLEncodeChars.length; j++) {
                var HTMLchar = HTMLEncodeChars.charCodeAt(j);
                if (theChar == HTMLchar) {
                    var asHex = theChar.toString(16);
                    var hexString = "&#x0000";
                    nextSegment =  hexString.substring(0, hexString.length - asHex.length) + asHex + ";";
                    break;
                }
            }
            retString = retString + nextSegment;
        }
        return retString;
    }

    var HTMLEncodeIdPData = function()
    {
        var i;
        for (i = 0; i < idpData.length; i++) {
            var j;
            var pos;
            displayNames = idpData[i].DisplayNames;
            if (displayNames == null) {
                continue;
            }
            for (j = 0; j < displayNames.length; j++) {
                pos = hasEncodingChars(displayNames[j].value);
                if (pos > 0) {
                    displayNames[j].value = HTMLEncode(displayNames[j].value, pos);
                }
            }
        }
    }
 
    // *************************************
    // Private functions
    //
    // Error Handling.  we'll keep it separate with a view to eventual
    //                  exbedding into log4js
    //
    // *************************************
    /**
       
    */

    var fatal = function(message) {
        alert('FATAL - DISCO UI:' + message);
        var txt = document.createTextNode(message); 
        idpSelectDiv.appendChild(txt);
    };

    var debug = function() {
        //
        // Nothing
    };
}
