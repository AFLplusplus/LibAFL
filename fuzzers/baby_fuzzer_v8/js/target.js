export default function(data) {
    if (data.length > 1 && data[0] === 'A'.charCodeAt(0)) {
        console.log("howdy")
        if (data.length > 2 && data[1] === 'B'.charCodeAt(0)) {
            console.log("kachowdy")
            if (data.length > 2 && data[2] === 'C'.charCodeAt(0)) {
                throw "crash!";
            }
        }
    }
}
