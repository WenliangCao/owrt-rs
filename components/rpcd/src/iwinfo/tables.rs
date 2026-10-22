//! iwinfo_lib.c: the public name tables (order and spelling identical to the
//! C arrays), the ht/vht/eht channel width tables and the ISO 3166 labels.

use super::Iso3166Label;

pub const IWINFO_80211_NAMES: [&str; 8] = ["a", "b", "g", "n", "ac", "ad", "ax", "be"];

pub const IWINFO_BAND_NAMES: [&str; 4] = ["2.4 GHz", "5 GHz", "6 GHz", "60 GHz"];

pub const IWINFO_CIPHER_NAMES: [&str; 11] = [
    "NONE", "WEP-40", "TKIP", "WRAP", "CCMP", "WEP-104", "AES-OCB", "CKIP", "GCMP", "CCMP-256",
    "GCMP-256",
];

pub const IWINFO_KMGMT_NAMES: [&str; 5] = ["NONE", "802.1X", "PSK", "SAE", "OWE"];

pub const IWINFO_AUTH_NAMES: [&str; 2] = ["OPEN", "SHARED"];

pub const IWINFO_OPMODE_NAMES: [&str; 10] = [
    "Unknown",
    "Master",
    "Ad-Hoc",
    "Client",
    "Monitor",
    "Master (VLAN)",
    "WDS",
    "Mesh Point",
    "P2P Client",
    "P2P Go",
];

pub const IWINFO_HTMODE_NAMES: [&str; 19] = [
    "HT20", "HT40", "VHT20", "VHT40", "VHT80", "VHT80+80", "VHT160", "NOHT", "HE20", "HE40",
    "HE80", "HE80+80", "HE160", "EHT20", "EHT40", "EHT80", "EHT80+80", "EHT160", "EHT320",
];

pub const IWINFO_FREQ_FLAG_NAMES: [&str; 9] = [
    "NO_10MHZ",
    "NO_20MHZ",
    "NO_HT40+",
    "NO_HT40-",
    "NO_80MHZ",
    "NO_160MHZ",
    "NO_HE",
    "NO_IR",
    "INDOOR_ONLY",
];

pub const HT_SECONDARY_OFFSET: [&str; 4] = ["no secondary", "above", "[reserved!]", "below"];

/// 0 = 20 MHz, 1 = 40 MHz or higher (refer to vht if supported)
pub const HT_CHAN_WIDTH: [u16; 2] = [20, 2040];

/// 0 = 40 MHz or lower, 1 = 80 MHz, 2 = 160 MHz, 3 = 80+80 MHz
pub const VHT_CHAN_WIDTH: [u16; 4] = [40, 80, 160, 8080];

/// 0 = 20, 1 = 40, 2 = 80, 3 = 80+80 or 160, 4 = 160+160 or 320 MHz
pub const EHT_CHAN_WIDTH: [u16; 5] = [20, 40, 80, 160, 320];

const fn l(iso3166: u16, name: &'static str) -> Iso3166Label {
    Iso3166Label { iso3166, name }
}

/// IWINFO_ISO3166_NAMES without the `{ 0, "" }` terminator (iterate the
/// slice instead of stopping at iso3166 == 0).
pub const IWINFO_ISO3166_NAMES: [Iso3166Label; 247] = [
    l(0x3030, "World"),
    l(0x4144, "Andorra"),
    l(0x4145, "United Arab Emirates"),
    l(0x4146, "Afghanistan"),
    l(0x4147, "Antigua and Barbuda"),
    l(0x4149, "Anguilla"),
    l(0x414C, "Albania"),
    l(0x414D, "Armenia"),
    l(0x414E, "Netherlands Antilles"),
    l(0x414F, "Angola"),
    l(0x4151, "Antarctica"),
    l(0x4152, "Argentina"),
    l(0x4153, "American Samoa"),
    l(0x4154, "Austria"),
    l(0x4155, "Australia"),
    l(0x4157, "Aruba"),
    l(0x4158, "Aland Islands"),
    l(0x415A, "Azerbaijan"),
    l(0x4241, "Bosnia and Herzegovina"),
    l(0x4242, "Barbados"),
    l(0x4244, "Bangladesh"),
    l(0x4245, "Belgium"),
    l(0x4246, "Burkina Faso"),
    l(0x4247, "Bulgaria"),
    l(0x4248, "Bahrain"),
    l(0x4249, "Burundi"),
    l(0x424A, "Benin"),
    l(0x424C, "Saint Barthelemy"),
    l(0x424D, "Bermuda"),
    l(0x424E, "Brunei Darussalam"),
    l(0x424F, "Bolivia"),
    l(0x4252, "Brazil"),
    l(0x4253, "Bahamas"),
    l(0x4254, "Bhutan"),
    l(0x4256, "Bouvet Island"),
    l(0x4257, "Botswana"),
    l(0x4259, "Belarus"),
    l(0x425A, "Belize"),
    l(0x4341, "Canada"),
    l(0x4343, "Cocos (Keeling) Islands"),
    l(0x4344, "Congo"),
    l(0x4346, "Central African Republic"),
    l(0x4347, "Congo"),
    l(0x4348, "Switzerland"),
    l(0x4349, "Cote d'Ivoire"),
    l(0x434B, "Cook Islands"),
    l(0x434C, "Chile"),
    l(0x434D, "Cameroon"),
    l(0x434E, "China"),
    l(0x434F, "Colombia"),
    l(0x4352, "Costa Rica"),
    l(0x4355, "Cuba"),
    l(0x4356, "Cape Verde"),
    l(0x4358, "Christmas Island"),
    l(0x4359, "Cyprus"),
    l(0x435A, "Czech Republic"),
    l(0x4445, "Germany"),
    l(0x444A, "Djibouti"),
    l(0x444B, "Denmark"),
    l(0x444D, "Dominica"),
    l(0x444F, "Dominican Republic"),
    l(0x445A, "Algeria"),
    l(0x4543, "Ecuador"),
    l(0x4545, "Estonia"),
    l(0x4547, "Egypt"),
    l(0x4548, "Western Sahara"),
    l(0x4552, "Eritrea"),
    l(0x4553, "Spain"),
    l(0x4554, "Ethiopia"),
    l(0x4649, "Finland"),
    l(0x464A, "Fiji"),
    l(0x464B, "Falkland Islands"),
    l(0x464D, "Micronesia"),
    l(0x464F, "Faroe Islands"),
    l(0x4652, "France"),
    l(0x4741, "Gabon"),
    l(0x4742, "United Kingdom"),
    l(0x4744, "Grenada"),
    l(0x4745, "Georgia"),
    l(0x4746, "French Guiana"),
    l(0x4747, "Guernsey"),
    l(0x4748, "Ghana"),
    l(0x4749, "Gibraltar"),
    l(0x474C, "Greenland"),
    l(0x474D, "Gambia"),
    l(0x474E, "Guinea"),
    l(0x4750, "Guadeloupe"),
    l(0x4751, "Equatorial Guinea"),
    l(0x4752, "Greece"),
    l(0x4753, "South Georgia"),
    l(0x4754, "Guatemala"),
    l(0x4755, "Guam"),
    l(0x4757, "Guinea-Bissau"),
    l(0x4759, "Guyana"),
    l(0x484B, "Hong Kong"),
    l(0x484D, "Heard and McDonald Islands"),
    l(0x484E, "Honduras"),
    l(0x4852, "Croatia"),
    l(0x4854, "Haiti"),
    l(0x4855, "Hungary"),
    l(0x4944, "Indonesia"),
    l(0x4945, "Ireland"),
    l(0x494C, "Israel"),
    l(0x494D, "Isle of Man"),
    l(0x494E, "India"),
    l(0x494F, "Chagos Islands"),
    l(0x4951, "Iraq"),
    l(0x4952, "Iran"),
    l(0x4953, "Iceland"),
    l(0x4954, "Italy"),
    l(0x4A45, "Jersey"),
    l(0x4A4D, "Jamaica"),
    l(0x4A4F, "Jordan"),
    l(0x4A50, "Japan"),
    l(0x4B45, "Kenya"),
    l(0x4B47, "Kyrgyzstan"),
    l(0x4B48, "Cambodia"),
    l(0x4B49, "Kiribati"),
    l(0x4B4D, "Comoros"),
    l(0x4B4E, "Saint Kitts and Nevis"),
    l(0x4B50, "North Korea"),
    l(0x4B52, "South Korea"),
    l(0x4B57, "Kuwait"),
    l(0x4B59, "Cayman Islands"),
    l(0x4B5A, "Kazakhstan"),
    l(0x4C41, "Laos"),
    l(0x4C42, "Lebanon"),
    l(0x4C43, "Saint Lucia"),
    l(0x4C49, "Liechtenstein"),
    l(0x4C4B, "Sri Lanka"),
    l(0x4C52, "Liberia"),
    l(0x4C53, "Lesotho"),
    l(0x4C54, "Lithuania"),
    l(0x4C55, "Luxembourg"),
    l(0x4C56, "Latvia"),
    l(0x4C59, "Libyan Arab Jamahiriya"),
    l(0x4D41, "Morocco"),
    l(0x4D43, "Monaco"),
    l(0x4D44, "Moldova"),
    l(0x4D45, "Montenegro"),
    l(0x4D46, "Saint Martin (French part)"),
    l(0x4D47, "Madagascar"),
    l(0x4D48, "Marshall Islands"),
    l(0x4D4B, "Macedonia"),
    l(0x4D4C, "Mali"),
    l(0x4D4D, "Myanmar"),
    l(0x4D4E, "Mongolia"),
    l(0x4D4F, "Macao"),
    l(0x4D50, "Northern Mariana Islands"),
    l(0x4D51, "Martinique"),
    l(0x4D52, "Mauritania"),
    l(0x4D53, "Montserrat"),
    l(0x4D54, "Malta"),
    l(0x4D55, "Mauritius"),
    l(0x4D56, "Maldives"),
    l(0x4D57, "Malawi"),
    l(0x4D58, "Mexico"),
    l(0x4D59, "Malaysia"),
    l(0x4D5A, "Mozambique"),
    l(0x4E41, "Namibia"),
    l(0x4E43, "New Caledonia"),
    l(0x4E45, "Niger"),
    l(0x4E46, "Norfolk Island"),
    l(0x4E47, "Nigeria"),
    l(0x4E49, "Nicaragua"),
    l(0x4E4C, "Netherlands"),
    l(0x4E4F, "Norway"),
    l(0x4E50, "Nepal"),
    l(0x4E52, "Nauru"),
    l(0x4E55, "Niue"),
    l(0x4E5A, "New Zealand"),
    l(0x4F4D, "Oman"),
    l(0x5041, "Panama"),
    l(0x5045, "Peru"),
    l(0x5046, "French Polynesia"),
    l(0x5047, "Papua New Guinea"),
    l(0x5048, "Philippines"),
    l(0x504B, "Pakistan"),
    l(0x504C, "Poland"),
    l(0x504D, "Saint Pierre and Miquelon"),
    l(0x504E, "Pitcairn"),
    l(0x5052, "Puerto Rico"),
    l(0x5053, "Palestinian Territory"),
    l(0x5054, "Portugal"),
    l(0x5057, "Palau"),
    l(0x5059, "Paraguay"),
    l(0x5141, "Qatar"),
    l(0x5245, "Reunion"),
    l(0x524F, "Romania"),
    l(0x5253, "Serbia"),
    l(0x5255, "Russian Federation"),
    l(0x5257, "Rwanda"),
    l(0x5341, "Saudi Arabia"),
    l(0x5342, "Solomon Islands"),
    l(0x5343, "Seychelles"),
    l(0x5344, "Sudan"),
    l(0x5345, "Sweden"),
    l(0x5347, "Singapore"),
    l(0x5348, "St. Helena and Dependencies"),
    l(0x5349, "Slovenia"),
    l(0x534A, "Svalbard and Jan Mayen"),
    l(0x534B, "Slovakia"),
    l(0x534C, "Sierra Leone"),
    l(0x534D, "San Marino"),
    l(0x534E, "Senegal"),
    l(0x534F, "Somalia"),
    l(0x5352, "Suriname"),
    l(0x5354, "Sao Tome and Principe"),
    l(0x5356, "El Salvador"),
    l(0x5359, "Syrian Arab Republic"),
    l(0x535A, "Swaziland"),
    l(0x5443, "Turks and Caicos Islands"),
    l(0x5444, "Chad"),
    l(0x5446, "French Southern Territories"),
    l(0x5447, "Togo"),
    l(0x5448, "Thailand"),
    l(0x544A, "Tajikistan"),
    l(0x544B, "Tokelau"),
    l(0x544C, "Timor-Leste"),
    l(0x544D, "Turkmenistan"),
    l(0x544E, "Tunisia"),
    l(0x544F, "Tonga"),
    l(0x5452, "Turkey"),
    l(0x5454, "Trinidad and Tobago"),
    l(0x5456, "Tuvalu"),
    l(0x5457, "Taiwan"),
    l(0x545A, "Tanzania"),
    l(0x5541, "Ukraine"),
    l(0x5547, "Uganda"),
    l(0x554D, "U.S. Minor Outlying Islands"),
    l(0x5553, "United States"),
    l(0x5559, "Uruguay"),
    l(0x555A, "Uzbekistan"),
    l(0x5641, "Vatican City State"),
    l(0x5643, "St. Vincent and Grenadines"),
    l(0x5645, "Venezuela"),
    l(0x5647, "Virgin Islands, British"),
    l(0x5649, "Virgin Islands, U.S."),
    l(0x564E, "Viet Nam"),
    l(0x5655, "Vanuatu"),
    l(0x5746, "Wallis and Futuna"),
    l(0x5753, "Samoa"),
    l(0x5945, "Yemen"),
    l(0x5954, "Mayotte"),
    l(0x5A41, "South Africa"),
    l(0x5A4D, "Zambia"),
    l(0x5A57, "Zimbabwe"),
];

/// Label lookup by the packed two-letter code (`'U' << 8 | 'S'`).
pub fn iso3166_name(iso3166: u16) -> Option<&'static str> {
    IWINFO_ISO3166_NAMES
        .iter()
        .find(|l| l.iso3166 == iso3166)
        .map(|l| l.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso3166_table() {
        assert_eq!(IWINFO_ISO3166_NAMES[0].name, "World");
        assert_eq!(IWINFO_ISO3166_NAMES[0].iso3166, 0x3030);
        assert_eq!(IWINFO_ISO3166_NAMES[246].name, "Zimbabwe");
        assert_eq!(
            iso3166_name(u16::from_be_bytes(*b"US")),
            Some("United States")
        );
        assert_eq!(iso3166_name(u16::from_be_bytes(*b"DE")), Some("Germany"));
        assert_eq!(iso3166_name(u16::from_be_bytes(*b"XX")), None);
        // ordered by code, as the C table is
        for w in IWINFO_ISO3166_NAMES.windows(2) {
            assert!(w[0].iso3166 < w[1].iso3166);
        }
    }

    #[test]
    fn name_tables() {
        assert_eq!(IWINFO_OPMODE_NAMES[5], "Master (VLAN)");
        assert_eq!(IWINFO_HTMODE_NAMES[18], "EHT320");
        assert_eq!(IWINFO_CIPHER_NAMES[10], "GCMP-256");
        assert_eq!(IWINFO_FREQ_FLAG_NAMES[2], "NO_HT40+");
        assert_eq!(VHT_CHAN_WIDTH[3], 8080);
    }
}
