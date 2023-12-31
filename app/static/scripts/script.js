
const makePrediction = (data) => {
    $.ajax({
        url: '/predict',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(data),
        success: function (response) {
            $("#prediction").text(response.prediction);
        },
        error: function (error) {
            $("#prediction").text("An error occurred.");
        }
    });
}

const formatTimeStamp = (data) => {
    let result = '';

    const label = {
        days: [
            'Senin', 'Selasa', 'Rabu', 'Kamis', "Jum'at", 'Sabtu', 'Minggu'
        ],
        months: [
            'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'
        ]
    }

    const raw = new Date(data);
    const day = raw.getUTCDay();
    const date = raw.getUTCDate();
    const month = raw.getUTCMonth();
    const year = raw.getFullYear();
    const hours = raw.getUTCHours();
    const minutes = raw.getUTCMinutes();
    const second = raw.getUTCSeconds();

    result = `${label.days[day]}, ${date} ${label.months[month]} ${year} ${hours}:${minutes}:${second}`

    return result;
}

const internalIP = async () => {
    if (!RTCPeerConnection) {
        throw new Error("Not supported.")
    }

    const peerConnection = new RTCPeerConnection({ iceServers: [] })

    peerConnection.createDataChannel('')
    peerConnection.createOffer(peerConnection.setLocalDescription.bind(peerConnection), () => { })

    peerConnection.addEventListener("icecandidateerror", (event) => {
        throw new Error(event.errorText)
    })

    return new Promise(async resolve => {
        peerConnection.addEventListener("icecandidate", async ({ candidate }) => {
            peerConnection.close()

            if (candidate && candidate.candidate) {
                const result = candidate.candidate.split(" ")[4]
                if (result.endsWith(".local")) {
                    const inputDevices = await navigator.mediaDevices.enumerateDevices()
                    const inputDeviceTypes = inputDevices.map(({ kind }) => kind)

                    const constraints = {}

                    if (inputDeviceTypes.includes("audioinput")) {
                        constraints.audio = true
                    } else if (inputDeviceTypes.includes("videoinput")) {
                        constraints.video = true
                    } else {
                        throw new Error("An audio or video input device is required!")
                    }

                    const mediaStream = await navigator.mediaDevices.getUserMedia(constraints)
                    mediaStream.getTracks().forEach(track => track.stop())
                    resolve(internalIp())
                }
                resolve(result)
            }
        })
    })
}


const updateIntrusionTable = () => {
    const prediction = [
        'Bukan Anomali',
        'Anomali',
    ]
    $.ajax({
        url: '/getIntrusions',
        type: 'GET',
        success: function (response) {
            $('#datatablesSimple tbody').empty();
            response.intrusions.forEach(function (intrusion, index) {
                const badgePrediction = intrusion.detection == 1 ? 'danger' : 'success'
                const badgeDuration = intrusion.duration > 10 ? 'danger' : 'success'
                const badgePacket = intrusion.pkt_len > 500 ? 'danger' : 'success'
                $('#datatablesSimple tbody').append(
                    '<tr><th scope="row">' + (index + 1) +
                    '</td><td>' + intrusion.ip_address +
                    '</td><td><span class="btn btn-' + badgeDuration + '">' + (intrusion.duration * 100).toFixed(4) +
                    ' ms</span></td><td><span class="btn btn-' + badgePacket + '">' + intrusion.pkt_len +
                    '</span></td><td><span class="btn btn-' + badgePrediction + '">' + prediction[intrusion.prediction] +
                    '</span></td><td>' + formatTimeStamp(intrusion.timestamp) +
                    '</td></tr>');
            });
        },
        error: function (error) {
            console.log("An error occurred while fetching intrusion data.");
        }
    });
}

const clearData = () =>
    swal.fire({
        title: 'Yakin Hapus Data?',
        html: 'Semua data di database akan terhapus!',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Ya, Hapus Data',
        cancelButtonText: 'Tidak',
        reverseButtons: true
    }).then((result) => {
        if (result.isConfirmed) {
            $.ajax({
                url: '/clear',
                type: 'GET',
                success: function (response) {
                    swal.fire({
                        title: 'Berhasil!',
                        html: 'Data Intrusion di dalam database berhasil dihapus',
                        icon: 'success',
                    })
                },
                error: function (error) {
                    swal.fire({
                        title: 'Gagal!',
                        html: 'Terjadi kesalahan saat hapus data',
                        icon: 'error'
                    })
                }
            });
        }

    })