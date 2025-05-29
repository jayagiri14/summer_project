const socket = io('/');

const videoGrid = document.getElementById('video-grid');
const myVideo = document.createElement('video');
myVideo.muted = true;

const chatMessage = document.getElementById('chat-message');
const chatBox = document.querySelector('.messages');

const audioButton = document.getElementById('audio-button');
const videoButton = document.getElementById('video-button');

var myPeer;
let myVideoStream;
const peerSet = new Set();
const userMap = new Map();

navigator.mediaDevices.getUserMedia({
    video: true,
    audio: true
}).then(stream => {
    userMap.set(stream.id, _userName);
    myVideoStream = stream;
    myPeer = new Peer(stream.id);
    myPeer.on('open', id => {
        socket.emit('join-room', _roomId, id, _userName);
    })
    addVideoStream(myVideo, stream);
    
    myPeer.on('call', call => {
        call.answer(myVideoStream);
        const video = document.createElement('video');
        call.on('stream', userVideoStream => {
            addVideoStream(video, userVideoStream);
        })
    })
})

socket.on('user-connected', (userId, userName, socketId) => {
    userMap.set(userId, userName);
    socket.emit('username-sent', socketId, myVideoStream.id, _userName, socket.id);
    connectToNewUser(userId);
})

socket.on('username-received', (userId, userName) => {
    userMap.set(userId, userName);
})

socket.on('message', (username, message) => {
    chatBox.innerHTML += `<li><p><b>${username}</b></p><p>${message}</p></li>`;
})

socket.on('user-disconnected', (userId) => {
    removeVideoStream(userId);
})

const connectToNewUser = (userId) => {
    const call = myPeer.call(userId, myVideoStream);
    const video = document.createElement('video');
    call.on('stream', userVideoStream => {
        addVideoStream(video, userVideoStream);
    })
}

const addVideoStream = (video, stream) => {
    if(!peerSet.has(stream.id)){
        peerSet.add(stream.id);
        video.srcObject = stream;
        video.addEventListener('loadedmetadata', () => {
            video.play();
        })
        const videoCard = document.createElement('div');
        const name = document.createElement('div');
        name.innerHTML = `<b>${userMap.get(stream.id)}</b>`;
        videoCard.append(video, name);
        videoCard.id = stream.id;
        videoCard.className = 'video-card';
        videoGrid.append(videoCard);
    }
}

const removeVideoStream = (userId) => {
    if(peerSet.has(userId)){
        peerSet.delete(userId);
        userMap.delete(userId);
        document.getElementById(userId).remove();
    }
}

function muteUnmute(){
    const enabled = myVideoStream.getAudioTracks()[0].enabled;
    if(enabled){
        myVideoStream.getAudioTracks()[0].enabled = false;
        audioButton.innerHTML = `<i class="fa-solid fa-microphone-slash" style="color: #ff0000;"></i>`;
    }
    else{
        myVideoStream.getAudioTracks()[0].enabled = true;
        audioButton.innerHTML = `<i class="fa-solid fa-microphone" style="color: #ffffff;"></i>`;
    }
}

function playStop(){
    const enabled = myVideoStream.getVideoTracks()[0].enabled;
    if(enabled){
        myVideoStream.getVideoTracks()[0].enabled = false;
        videoButton.innerHTML = `<i class="fa-solid fa-video-slash" style="color: #ff0000;"></i>`;
    }
    else{
        myVideoStream.getVideoTracks()[0].enabled = true;
        videoButton.innerHTML = `<i class="fa-solid fa-video" style="color: #ffffff;"></i>`;
    }
}

function sendMessage(event){
    if(event.key == "Enter" && chatMessage.value !== ''){ 
        chatBox.innerHTML += `<li><p><b>${_userName}</b></p><p>${chatMessage.value}</p></li>`;
        socket.emit('message', _userName, chatMessage.value);
        chatMessage.value = '';
    }
}

function leaveMeeting(){
    socket.disconnect();
    return true;
}