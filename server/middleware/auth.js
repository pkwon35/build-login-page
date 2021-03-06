const {User} = require('../models/User')

let auth = (req,res,next) => {

    // 인증처리를 하는곳 
    
    // 클라이언트 쿠키에서 토큰을 가져온다
    let token = req.cookies.x_auth; // x_auth 는 내가 기존에 지정한 이름으로

    // 토큰을 복호화 한후 유저를 찾는다
    User.findByToken(token,(err,user)=>{
        if(err) throw err;
        if(!user) return res.json({ isAuth:false, error:true})


        req.token = token;
        req.user = user;
        next();   //미드웨어에서 할꺼 다 하고나면 진행 할 수 있게

    })
    // 유저가 있으면 인증 OKAY

    // 유저가 없으면 인증 NO!
}

module.exports = {auth};