// pinched from https://stackoverflow.com/questions/16826200/javascript-silly-name-generator
let name_parts = [
	["Runny", "Buttercup", "Dinky", "Stinky", "Crusty",
	"Greasy","Gidget", "Cheesypoof", "Lumpy", "Wacky", "Tiny", "Flunky",
	"Fluffy", "Zippy", "Doofus", "Gobsmacked", "Slimy", "Grimy", "Salamander",
	"Oily", "Burrito", "Bumpy", "Loopy", "Snotty", "Irving", "Egbert"],

	["Waffer", "Lilly","Rugrat","Sand", "Fuzzy","Kitty",
	 "Puppy", "Snuggles","Rubber", "Stinky", "Lulu", "Lala", "Sparkle", "Glitter",
	 "Silver", "Golden", "Rainbow", "Cloud", "Rain", "Stormy", "Wink", "Sugar",
	 "Twinkle", "Star", "Halo", "Angel"],
	["Snicker", "Buffalo", "Gross", "Bubble", "Sheep",
	 "Corset", "Toilet", "Lizard", "Waffle", "Kumquat", "Burger", "Chimp", "Liver",
	 "Gorilla", "Rhino", "Emu", "Pizza", "Toad", "Gerbil", "Pickle", "Tofu", 
	"Chicken", "Potato", "Hamster", "Lemur", "Vermin"],
	["face", "dip", "nose", "brain", "head", "breath", 
	"pants", "shorts", "lips", "mouth", "muffin", "butt", "bottom", "elbow", 
	"honker", "toes", "buns", "spew", "kisser", "fanny", "squirt", "chunks", 
	"brains", "wit", "juice", "shower"],
];

function generateName() {
	name = '';
	for (let i = 0; i < name_parts.length; i++) {
		if (i > 0 && i < 3) {
			name += ' ';
		}
		const ii = Math.random() * name_parts[i].length;
		name += name_parts[i][Math.floor(ii)];
	}
	return name;
}
