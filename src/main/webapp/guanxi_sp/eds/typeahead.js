function TypeAheadControl(jsonObj, box, orig, submit, maxchars, getName, getEntityId, geticon, ie6hack)
{
    //
    // Squirrel away the parameters we were given
    //
    this.elementList = jsonObj;
    this.textBox = box;
    this.origin = orig;
    this.submit = submit;
    this.results = 0;
    this.maxResults = 35;
    this.ie6hack = ie6hack;
    this.maxchars = maxchars;
    this.getName = getName;
    this.getEntityId = getEntityId;
    this.geticon = geticon;
}

TypeAheadControl.prototype.draw = function() {

    //
    // Make a closure on this so that the embedded functions
    // get access to it.
    //
    var myThis = this;
   
    //
    // Set up the 'dropDown'
    //
    this.dropDown = document.createElement('div');
    this.dropDown.className = 'IdPSelectDropDown';
    this.dropDown.style.visibility = 'hidden';

    this.dropDown.style.width = this.textBox.offsetWidth;
    this.dropDown.current = -1;
    document.body.appendChild(this.dropDown);

    //
    // mouse listeners for the dropdown box
    //
    this.dropDown.onmouseover = function(event) {
        if (!event) {
            event = window.event;
        }
        var target;
        if (event.target){
            target = event.target;
        }
        if (typeof target == 'undefined') {
            target = event.srcElement;
        }
        myThis.select(target);
    };
   
    this.dropDown.onmousedown = function(event) {
        if (-1 != myThis.dropDown.current) {
            myThis.textBox.value = myThis.results[myThis.dropDown.current][0];
        }
    };

    //
    // Add the listeners to the text box
    //
    this.textBox.onkeyup = function(event) {
        //
        // get window event if needed (because of browser oddities)
        //
        if (!event) {
            event = window.event;
        }
        myThis.handleKeyUp(event);
    };

    this.textBox.onkeydown = function(event) {
        if (!event) {
            event = window.event;
        }

        myThis.handleKeyDown(event);
    };

    this.textBox.onblur = function() {
        myThis.hideDrop();
    };

    this.textBox.onfocus = function() {
        myThis.handleChange();
    };

};

//
// Given a name return the first maxresults, or all possibles
//
TypeAheadControl.prototype.getPossible = function(name) {
    var possibles = [];
    var inIndex = 0;
    var outIndex = 0;
    var strIndex = 0;
    var str;
    var ostr;

    name = name.toLowerCase();
        
    while (outIndex <= this.maxResults && inIndex < this.elementList.length) {
        var hit = false;
        var i;
        var thisName = this.getName(this.elementList[inIndex]);

        //
        // Check name
        //
        i = 0;
        if (thisName.toLowerCase().indexOf(name) != -1) {
            hit = true;
        }  
        //
        // Check entityID
        //
        if (!hit && this.getEntityId(this.elementList[inIndex]).toLowerCase().indexOf(name) != -1) {
            hit = true;
        }
                
        if (hit) {
            possibles[outIndex] = [thisName, this.getEntityId(this.elementList[inIndex]), this.geticon(this.elementList[inIndex])];
            outIndex ++;
        }
                
        inIndex ++;
    }
    //
    // reset the cursor to the top
    //
    this.dropDown.current = -1;
    
    return possibles;
};

TypeAheadControl.prototype.handleKeyUp = function(event) {
    var key = event.keyCode;

    if (27 == key) {
        //
        // Escape - clear
        //
        this.textBox.value = '';
        this.handleChange();
    } else if (8 == key || 32 == key || (key >= 46 && key < 112) || key > 123) {
        //
        // Backspace, Space and >=Del to <F1 and > F12
        //
        this.handleChange();
    }
};
 
TypeAheadControl.prototype.handleKeyDown = function(event) {

    var key = event.keyCode;

    if (38 == key) {
        //
        // up arrow
        //
        this.upSelect();

    } else if (40 == key) {
        //
        // down arrow
        //
        this.downSelect();
    }
};

TypeAheadControl.prototype.hideDrop = function() {
    var i = 0;
    if (null != this.ie6hack) {
        while (i < this.ie6hack.length) {
            this.ie6hack[i].style.visibility = 'visible';
            i++;
        }
    }
    this.dropDown.style.visibility = 'hidden';

    if (-1 == this.dropDown.current) {
        this.doUnselected();
    }
};

TypeAheadControl.prototype.showDrop = function() {
    var i = 0;
    if (null != this.ie6hack) {
        while (i < this.ie6hack.length) {
            this.ie6hack[i].style.visibility = 'hidden';
            i++;
        }
    }
    this.dropDown.style.visibility = 'visible';
};


TypeAheadControl.prototype.doSelected = function() {
    this.submit.disabled = false;
};

TypeAheadControl.prototype.doUnselected = function() {
    this.submit.disabled = true;
};

TypeAheadControl.prototype.handleChange = function() {

    var val = this.textBox.value;
    var res = this.getPossible(val);


    if (0 == res.length || this.maxResults < res.length) {
        this.hideDrop();
        this.doUnselected();
        this.results = [];
        this.dropDown.current = -1;
    } else {
        this.results = res;
        this.populateDropDown(res);
        if (1 == res.length) {
            this.select(this.dropDown.childNodes[0]);
            this.doSelected();
        } else {
            this.doUnselected();
        }
    }
};

//
// A lot of the stuff below comes from 
// http://www.webreference.com/programming/javascript/ncz/column2
//
// With thanks to Nicholas C Zakas
//
TypeAheadControl.prototype.populateDropDown = function(list) {
    this.dropDown.innerHTML = '';
    var i = 0;
    var div;
    var img;
    var str;

    while (i < list.length) {
        div = document.createElement('div');
        var str = list[i][0];

	if (null != list[i][2]) {

	    img = document.createElement('img');
	    img.src = list[i][2];
	    img.width = 16;
	    img.height = 16;
	    img.alt = '';
	    div.appendChild(img);
	    //
	    // trim string back further in this case
	    //
	    if (str.length > this.maxchars - 2) {
		str = str.substring(0, this.maxchars - 2);
	    }
	    str = ' ' + str;
	} else {
	    if (str.length > this.maxchars) {
		str = str.substring(0, this.maxchars);
	    }
	}
        div.appendChild(document.createTextNode(str));

        this.dropDown.appendChild(div);
        i++;
    }
    var off = this.getXY();
    this.dropDown.style.left = off[0] + 'px';
    this.dropDown.style.top = off[1] + 'px';
    this.showDrop();
};

TypeAheadControl.prototype.getXY = function() {

    var node = this.textBox;
    var sumX = 0;
    var sumY = node.offsetHeight;
   
    while(node.tagName != 'BODY') {
        sumX += node.offsetLeft;
        sumY += node.offsetTop;
        node = node.offsetParent;
    }
    //
    // And add in the offset for the Body
    //
    sumX += node.offsetLeft;
    sumY += node.offsetTop;

    return [sumX, sumY];
};

TypeAheadControl.prototype.select = function(selected) {
    var i = 0;
    var node;
    this.dropDown.current = -1;
    this.doUnselected();
    while (i < this.dropDown.childNodes.length) {
        node = this.dropDown.childNodes[i];
        if (node == selected) {
            //
            // Highlight it
            //
            node.className = 'IdPSelectCurrent';
            //
            // turn on the button
            //
            this.doSelected();
            //
            // setup the cursor
            //
            this.dropDown.current = i;
            //
            // and the value for the Server
            //
            this.origin.value = this.results[i][1];
            this.origin.textValue = this.results[i][0];
        } else {
            node.className = '';
        }
        i++;
    }
    this.textBox.focus();
};

TypeAheadControl.prototype.downSelect = function() {
    if (this.results.length > 0) {

        if (-1 == this.dropDown.current) {
            //
            // mimic a select()
            //
            this.dropDown.current = 0;
            this.dropDown.childNodes[0].className = 'IdPSelectCurrent';
            this.doSelected();
            this.origin.value = this.results[0][1];
            this.origin.textValue = this.results[0][0];

        } else if (this.dropDown.current < (this.results.length-1)) {
            //
            // turn off highlight
            //
            this.dropDown.childNodes[this.dropDown.current].className = '';
            //
            // move cursor
            //
            this.dropDown.current++;
            //
            // and 'select'
            //
            this.dropDown.childNodes[this.dropDown.current].className = 'IdPSelectCurrent';
            this.doSelected();
            this.origin.value = this.results[this.dropDown.current][1];
            this.origin.textValue = this.results[this.dropDown.current][0];

        }
    }
};


TypeAheadControl.prototype.upSelect = function() {
    if ((this.results.length > 0) &&
        (this.dropDown.current > 0)) {
    
            //
            // turn off highlight
            //
            this.dropDown.childNodes[this.dropDown.current].className = '';
            //
            // move cursor
            //
            this.dropDown.current--;
            //
            // and 'select'
            //
            this.dropDown.childNodes[this.dropDown.current].className = 'IdPSelectCurrent';
            this.doSelected();
            this.origin.value = this.results[this.dropDown.current][1];
            this.origin.textValue = this.results[this.dropDown.current][0];
        }
};
