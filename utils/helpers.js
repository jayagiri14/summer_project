const bcrypt = require('bcrypt');

async function HashPassword(password) {
    const salt = await bcrypt.genSalt();
    return await bcrypt.hash(password , salt);
}

async function ComparePassword(password , hashedPasswd)
{
    return await bcrypt.compare(password , hashedPasswd);
}

function GenerateCode()
{
    var str = "";
    for (let i = 0; i < 5; i++)
    {
        const p = Math.random();
        if (p > 0.66) str += String.fromCharCode(97 + Math.floor(Math.random() * 26));
        else if (p > 0.33) str += String.fromCharCode(65 + Math.floor(Math.random() * 26));
        else str += String.fromCharCode(48 + Math.floor(Math.random() * 10));
    }
    return str;
}

module.exports = {HashPassword , ComparePassword , GenerateCode};